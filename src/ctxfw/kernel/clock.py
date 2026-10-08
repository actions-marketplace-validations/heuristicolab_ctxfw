"""Injectable UTC clock for the Sovereign Pentad kernel.

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000
manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3

TraceKit has no internal clock: every timestamp is supplied by the caller and must be UTC-aware.
Audit code receives a ``Clock``; only the *host* composition root builds ``SystemUtcClock``.
"""
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "FixedClock", "SystemClock", "SystemUtcClock", "require_utc"]


def require_utc(value: object) -> datetime:
    """Return ``value`` if it is a UTC-aware ``datetime``; raise ``ValueError`` otherwise.

    Naive datetimes and non-zero offsets are rejected, never converted.
    """
    if not isinstance(value, datetime):
        raise ValueError("timestamp must be a datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC (offset 0)")
    return value


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime:  # pragma: no cover - protocol
        ...


class SystemUtcClock:
    """Host-side adapter over the wall clock. Never constructed by audit/kernel internals."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


SystemClock = SystemUtcClock


class FixedClock:
    """Deterministic clock for tests and replays; advances only through ``advance``."""

    def __init__(self, start: datetime) -> None:
        self._now = require_utc(start)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> datetime:
        if delta < timedelta(0):
            raise ValueError("a FixedClock never moves backwards")
        self._now = require_utc(self._now + delta)
        return self._now
