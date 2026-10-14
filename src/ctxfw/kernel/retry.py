"""Bounded WAL retry envelope for the Sovereign Pentad kernel.

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000
manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3

Contract (identical to the sealed blueprints): at most 3 *retries* after the first attempt, with
backoff 0.02 s, 0.04 s, 0.08 s. Only transient SQLite lock/busy errors are retried; anything else
propagates immediately. On exhaustion a ``RetryExhausted`` is raised (class TRANSIENT) so the caller
takes the module's fail-closed terminal path. Nothing is ever printed.
"""
import sqlite3
import time
from typing import Callable, Optional, TypeVar

__all__ = [
    "MAX_RETRIES",
    "RETRY_BACKOFF_SECONDS",
    "RetryExhausted",
    "is_transient_sqlite_error",
    "run_with_wal_retry",
]

T = TypeVar("T")

MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = (0.02, 0.04, 0.08)

_TRANSIENT_MARKERS = ("database is locked", "database table is locked", "database is busy")


class RetryExhausted(Exception):
    """All bounded retries failed with transient errors (failure class TRANSIENT)."""

    def __init__(self, attempts: int, last_error: BaseException) -> None:
        super().__init__(f"WAL operation still failing after {attempts} attempts: {last_error}")
        self.attempts = attempts
        self.last_error = last_error


def is_transient_sqlite_error(error: BaseException) -> bool:
    if not isinstance(error, sqlite3.OperationalError):
        return False
    message = str(error).lower()
    return any(marker in message for marker in _TRANSIENT_MARKERS)


def run_with_wal_retry(
    operation: Callable[[], T],
    *,
    is_transient: Callable[[BaseException], bool] = is_transient_sqlite_error,
    sleep: Optional[Callable[[float], None]] = None,
) -> T:
    """Run ``operation`` with the bounded transient-retry policy."""
    pause = time.sleep if sleep is None else sleep
    attempts = 0
    while True:
        attempts += 1
        try:
            return operation()
        except Exception as error:
            if not is_transient(error):
                raise
            retries_used = attempts - 1
            if retries_used >= MAX_RETRIES:
                raise RetryExhausted(attempts, error) from error
            pause(RETRY_BACKOFF_SECONDS[retries_used])
