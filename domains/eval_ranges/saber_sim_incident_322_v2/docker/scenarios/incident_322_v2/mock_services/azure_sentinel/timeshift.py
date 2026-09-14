"""Timestamp normalization for historical log ingestion.

Why: bundle logs are timestamped at GENERATION time. When a container starts
later, KQL `ago(...)` windows (relative to wall-clock now) filter them ALL out,
so detections that correctly time-bound their queries return zero rows. This
shifts every record's time fields forward by ONE global delta so the newest event
lands at ~now — making `ago()` / time-window queries execute, while PRESERVING the
relative spacing between events (so correlation windows like
`between (T .. T + 30m)` stay valid).

Pure functions — unit tested in tests/test_timeshift.py. No I/O here; the caller
(log_collector.load_historical_logs) does the two passes (find max, then shift).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

# Event-timestamp field names across the Sentinel / Azure Monitor schemas we ingest.
TIME_FIELDS: tuple[str, ...] = (
    "TimeGenerated",
    "time",
    "timestamp",
    "Timestamp",
    "TimeCreated",
    "createdDateTime",
    "EventTime",
    "StartTime",
    "EndTime",
    "GeneratedTime",
    "IngestionTime",
)

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def parse_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601-ish timestamp string into an aware UTC datetime, or None."""
    if not isinstance(value, str) or not _ISO_RE.match(value):
        return None
    s = value.strip().replace("Z", "+00:00")
    for candidate in (s, s[:26], s[:19]):  # tolerate >6 fractional digits / no tz
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def record_max_dt(record: dict[str, Any]) -> datetime | None:
    """Max parseable timestamp among a record's known time fields (or None)."""
    best: datetime | None = None
    for k in TIME_FIELDS:
        if k in record:
            dt = parse_dt(record.get(k))
            if dt and (best is None or dt > best):
                best = dt
    return best


def compute_shift_seconds(global_max: datetime | None, now: datetime) -> float:
    """Seconds to ADD so the global-max event lands at `now`.

    Only shifts STALE (past) data forward. If the data is already at/after now,
    returns 0 — never shifts backward (that would hide recent live data).
    """
    if global_max is None:
        return 0.0
    delta = (now - global_max).total_seconds()
    return delta if delta > 0 else 0.0


def shift_record(record: dict[str, Any], delta_seconds: float) -> dict[str, Any]:
    """Shift all known time fields in `record` by `delta_seconds` (mutates + returns).

    Preserves the original string flavor (trailing 'Z' vs '+00:00') so downstream
    Kusto ingest sees the same format it expected.
    """
    if not delta_seconds:
        return record
    for k in TIME_FIELDS:
        if k not in record:
            continue
        dt = parse_dt(record.get(k))
        if not dt:
            continue
        shifted = (dt + timedelta(seconds=delta_seconds)).astimezone(timezone.utc)
        iso = shifted.isoformat()
        orig = record[k]
        record[k] = iso.replace("+00:00", "Z") if isinstance(orig, str) and orig.endswith("Z") else iso
    return record
