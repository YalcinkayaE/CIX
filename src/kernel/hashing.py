from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """
    Deterministic JSON serialization (JCS-style):
    - Sorted keys
    - No extra whitespace
    - UTF-8 safe
    """
    if isinstance(obj, (dict, list)):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return str(obj)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_payload(obj: Any) -> str:
    return f"sha256:{sha256_hex(canonical_json(obj))}"
