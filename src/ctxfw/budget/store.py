# manifest_hash: 862e0dc20133fe81f2ce12812b86d74068db80cce8566a3b71d2d406db72c549
"""
TokenCast Store :: SQLite WAL Append-Only Ledger Persistence
============================================================
Persists session budgets, turn telemetry, and enforcement decisions over SQLite WAL.
Enforces the 9 sealed DDL triggers and deterministic bounded retry on concurrency lock.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, TypeVar, Union

from ctxfw.budget import load_schema_sql
from ctxfw.budget.contracts import (
    DecisionKind,
    SessionTokenBudgetDTO,
    derive_ledger_id,
)

__all__ = ["TokenCastStore"]

T = TypeVar("T")


class TokenCastStore:
    """Thread-safe SQLite WAL persistence store for TokenCast."""

    def __init__(self, db_path: Union[str, Path] = ":memory:") -> None:
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self._db_path,
            timeout=5.0,
            check_same_thread=False,
            isolation_level=None,  # autocommit mode, manual transactions
        )
        self._configure_connection(self._conn)
        self.init_db()

    @staticmethod
    def _configure_connection(conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")

    def _execute_with_retry(self, operation: Callable[[sqlite3.Connection], T]) -> T:
        max_retries = 3
        for attempt in range(max_retries + 1):
            try:
                with self._lock:
                    return operation(self._conn)
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if ("locked" in msg or "busy" in msg) and attempt < max_retries:
                    time.sleep(0.01 * (2 ** attempt))
                    continue
                raise

    def init_db(self) -> None:
        """Idempotently initialize the sealed DDL schema."""
        def _init(conn: sqlite3.Connection) -> None:
            conn.executescript(load_schema_sql())

        self._execute_with_retry(_init)

    def create_session_budget(self, budget: SessionTokenBudgetDTO) -> None:
        """Insert a parent session budget row."""
        if not isinstance(budget, SessionTokenBudgetDTO):
            raise TypeError(f"budget must be SessionTokenBudgetDTO, got {type(budget).__name__}")

        def _insert(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO tokencast_session_budgets
                    (session_id, soft_limit_tokens, hard_limit_tokens, max_turns)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        budget.session_id,
                        budget.soft_limit_tokens,
                        budget.hard_limit_tokens,
                        budget.max_turns,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        self._execute_with_retry(_insert)

    def record_turn_telemetry(
        self,
        session_id: str,
        turn_index: int,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> str:
        """Record turn telemetry and return derived telemetry_id.

        Tokens used is prompt_tokens + completion_tokens.
        """
        tokens_used = prompt_tokens + completion_tokens
        telemetry_id = derive_ledger_id("TEL-", session_id, turn_index)

        def _insert(conn: sqlite3.Connection) -> str:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO tokencast_turn_telemetry
                    (telemetry_id, session_id, turn_index, tokens_used)
                    VALUES (?, ?, ?, ?)
                    """,
                    (telemetry_id, session_id, turn_index, tokens_used),
                )
                conn.execute("COMMIT")
                return telemetry_id
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self._execute_with_retry(_insert)

    def record_enforcement_decision(
        self,
        session_id: str,
        decision: Union[DecisionKind, str],
        forecast_tokens: int,
    ) -> str:
        """Record an enforcement decision event and return derived event_id."""
        decision_str = decision.value if isinstance(decision, DecisionKind) else str(decision)

        def _insert(conn: sqlite3.Connection) -> str:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM tokencast_enforcement_events WHERE session_id = ?",
                    (session_id,),
                )
                count = cur.fetchone()[0]
                event_id = derive_ledger_id("EVT-", session_id, decision_str, forecast_tokens, count)

                conn.execute(
                    """
                    INSERT INTO tokencast_enforcement_events
                    (event_id, session_id, decision, forecast_tokens)
                    VALUES (?, ?, ?, ?)
                    """,
                    (event_id, session_id, decision_str, forecast_tokens),
                )
                conn.execute("COMMIT")
                return event_id
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self._execute_with_retry(_insert)

    def get_session_budget(self, session_id: str) -> dict[str, Any] | None:
        """Fetch budget record as a dictionary."""
        def _query(conn: sqlite3.Connection) -> dict[str, Any] | None:
            cur = conn.execute(
                """
                SELECT session_id, soft_limit_tokens, hard_limit_tokens, max_turns, created_at
                FROM tokencast_session_budgets
                WHERE session_id = ?
                """,
                (session_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "session_id": row[0],
                "soft_limit_tokens": row[1],
                "hard_limit_tokens": row[2],
                "max_turns": row[3],
                "created_at": row[4],
            }

        return self._execute_with_retry(_query)

    def get_turn_telemetry(self, session_id: str) -> list[dict[str, Any]]:
        """Fetch all turn telemetry rows for session ordered by turn_index."""
        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT telemetry_id, session_id, turn_index, tokens_used, created_at
                FROM tokencast_turn_telemetry
                WHERE session_id = ?
                ORDER BY turn_index ASC
                """,
                (session_id,),
            )
            return [
                {
                    "telemetry_id": r[0],
                    "session_id": r[1],
                    "turn_index": r[2],
                    "tokens_used": r[3],
                    "created_at": r[4],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def get_enforcement_events(self, session_id: str) -> list[dict[str, Any]]:
        """Fetch all enforcement events for session ordered by rowid."""
        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT event_id, session_id, decision, forecast_tokens, created_at
                FROM tokencast_enforcement_events
                WHERE session_id = ?
                ORDER BY rowid ASC
                """,
                (session_id,),
            )
            return [
                {
                    "event_id": r[0],
                    "session_id": r[1],
                    "decision": r[2],
                    "forecast_tokens": r[3],
                    "created_at": r[4],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "TokenCastStore":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
