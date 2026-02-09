from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple


DEFAULT_EXCLUDE_FIELDS = [
    "timestamp",
    "@timestamp",
    "event_timestamp",
    "time",
    "datetime",
    "_normalized_timestamp",
    "id",
    "event_id",
    "eventId",
    "_id",
    "uuid",
]


def compute_event_hash(event: Dict[str, Any], exclude_fields: Optional[List[str]] = None) -> str:
    """
    Compute stable content hash for an event by excluding volatile identifiers.
    Mirrors axoden-sfa content hash semantics.
    """
    if exclude_fields is None:
        exclude_fields = DEFAULT_EXCLUDE_FIELDS

    filtered = {k: v for k, v in event.items() if k not in exclude_fields}
    try:
        content = json.dumps(filtered, sort_keys=True, default=str)
    except Exception:
        content = str(sorted(filtered.items()))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def deduplicate_events(
    events: List[Dict[str, Any]], exclude_fields: Optional[List[str]] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Deduplicate events by exact content hash (preserves first occurrence).
    Returns (deduplicated_events, duplicates_removed).
    """
    if not events:
        return [], 0

    seen: Set[str] = set()
    deduped: List[Dict[str, Any]] = []
    duplicates_removed = 0

    for event in events:
        event_hash = compute_event_hash(event, exclude_fields)
        if event_hash in seen:
            duplicates_removed += 1
            continue
        seen.add(event_hash)
        deduped.append(event)

    return deduped, duplicates_removed
