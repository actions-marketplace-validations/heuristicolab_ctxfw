# manifest_hash: 8f925c1e7c680c7af68e6f3daa48a5ac734923438762ed8836878a97508ce42e
"""
SARA Audit Sink :: SQLite WAL Append-Only Execution Log & Quarantine Isolation
==============================================================================
Persists authorized tool policies, append-only execution logs (storing only the
SHA-256 observation digest, never raw_output), and isolated quarantine payloads
for QUARANTINE_TOOL verdicts in a single atomic SQLite WAL transaction.
"""
from __future__ import annotations

import math
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional, Tuple, TypeVar, Union

from ctxfw.sara import load_schema_sql
from ctxfw.sara.contracts import (
    AuthorizationPolicyRuleDTO,
    AuthorizationVerdictDTO,
    RawToolObservationDTO,
    SaraEvent,
    SaraState,
    VerdictKind,
    observation_digest,
    transition,
)

# Architectural aliases
UntrustedObservationDTO = RawToolObservationDTO
AuthorizedPolicyDTO = AuthorizationPolicyRuleDTO

__all__ = [
    "AuditSink",
    "AuthorizedPolicyDTO",
    "UntrustedObservationDTO",
    "derive_quarantine_id",
]

T = TypeVar("T")


def derive_quarantine_id(execution_id: str) -> str:
    """Derive canonical quarantine_id ('QRN-' + execution_id[4:]) from an execution_id."""
    if not isinstance(execution_id, str) or not execution_id.startswith("EXE-") or len(execution_id) < 12:
        raise ValueError(f"Invalid execution_id for quarantine derivation: {execution_id!r}")
    return "QRN-" + execution_id[4:]


def _pre_commit_state_for_verdict(verdict: VerdictKind) -> SaraState:
    if verdict is VerdictKind.ALLOW:
        return SaraState.AUTHORIZED_ALLOW
    if verdict is VerdictKind.STRIP_COMMANDS:
        return SaraState.AUTHORIZED_STRIPPED
    return SaraState.QUARANTINED


def _resolve_observation_and_verdict(
    first: Any,
    second: Any = None,
    *,
    observation_sha256: Optional[str] = None,
    raw_output: Optional[str] = None,
) -> Tuple[AuthorizationVerdictDTO, str, str]:
    """Unpack flexible (observation, verdict) or (verdict, observation) arguments."""
    if isinstance(first, RawToolObservationDTO) and isinstance(second, AuthorizationVerdictDTO):
        obs = first
        verdict = second
        if obs.source.execution_id != verdict.execution_id:
            raise ValueError("observation.source.execution_id does not match verdict.execution_id")
        if obs.source.tool_name != verdict.tool_name:
            raise ValueError("observation.source.tool_name does not match verdict.tool_name")
        return verdict, obs.observation_sha256, obs.raw_output

    if isinstance(first, AuthorizationVerdictDTO) and isinstance(second, RawToolObservationDTO):
        verdict = first
        obs = second
        if obs.source.execution_id != verdict.execution_id:
            raise ValueError("observation.source.execution_id does not match verdict.execution_id")
        if obs.source.tool_name != verdict.tool_name:
            raise ValueError("observation.source.tool_name does not match verdict.tool_name")
        return verdict, obs.observation_sha256, obs.raw_output

    if isinstance(first, AuthorizationVerdictDTO):
        verdict = first
        sha256 = second if isinstance(second, str) else observation_sha256
        raw = raw_output if raw_output is not None else ""
        if sha256 is None:
            sha256 = observation_digest(raw)
        return verdict, sha256, raw

    raise TypeError(
        "Expected (RawToolObservationDTO, AuthorizationVerdictDTO) or "
        "(AuthorizationVerdictDTO, RawToolObservationDTO)"
    )


class AuditSink:
    """Thread-safe SQLite WAL persistence and quarantine isolation sink for SARA."""

    MAX_RETRIES: int = 3

    def __init__(self, db_path: Union[str, Path, sqlite3.Connection] = ":memory:") -> None:
        self._lock = threading.RLock()
        if isinstance(db_path, sqlite3.Connection):
            self._db_path = ":connection:"
            self._conn = db_path
            self._owns_connection = False
        else:
            self._db_path = str(db_path)
            self._conn = sqlite3.connect(
                self._db_path,
                timeout=5.0,
                check_same_thread=False,
                isolation_level=None,
            )
            self._owns_connection = True
        self._configure_connection(self._conn)
        self.init_db()

    @property
    def connection(self) -> sqlite3.Connection:
        """Underlying SQLite connection."""
        return self._conn

    @staticmethod
    def _configure_connection(conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")

    def _execute_with_retry(self, operation: Callable[[sqlite3.Connection], T]) -> T:
        """Execute a database operation with bounded exponential backoff (max 3 retries)."""
        max_retries = self.MAX_RETRIES
        for attempt in range(max_retries + 1):
            try:
                with self._lock:
                    return operation(self._conn)
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if ("locked" in msg or "busy" in msg) and attempt < max_retries:
                    time.sleep(0.01 * (2**attempt))
                    continue
                raise
        raise sqlite3.OperationalError("SQLite retry loop exhausted")  # pragma: no cover

    def init_db(self) -> None:
        """Idempotently initialize the sealed SARA relational schema and triggers."""

        def _init(conn: sqlite3.Connection) -> None:
            conn.executescript(load_schema_sql())
            self._configure_connection(conn)

        self._execute_with_retry(_init)

    def register_policy(self, policy: AuthorizedPolicyDTO) -> str:
        """Register an immutable authorization policy in sara_authorized_policies."""
        if not isinstance(policy, AuthorizationPolicyRuleDTO):
            raise TypeError(
                f"policy must be AuthorizationPolicyRuleDTO, got {type(policy).__name__}"
            )

        def _insert(conn: sqlite3.Connection) -> str:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO sara_authorized_policies
                    (policy_id, tool_name, policy_mask)
                    VALUES (?, ?, ?)
                    """,
                    (policy.policy_id, policy.tool_name, policy.policy_mask),
                )
                conn.execute("COMMIT")
                return policy.policy_id
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        return self._execute_with_retry(_insert)

    def audit_commit(
        self,
        first: Any,
        second: Any = None,
        *,
        observation_sha256: Optional[str] = None,
        raw_output: Optional[str] = None,
        state: Optional[SaraState] = None,
    ) -> SaraState:
        """Atomically persist an execution verdict and (if QUARANTINE_TOOL) its quarantine payload.

        Guarantees:
          - INV-09: sara_tool_execution_logs never stores raw_output, only observation_sha256.
          - Composite transaction: when verdict == QUARANTINE_TOOL, inserts into
            sara_tool_execution_logs first and sara_quarantine_payloads second within
            the same IMMEDIATE transaction, satisfying trg_sara_quarantine_requires_verdict.
          - Returns the terminal FSM state transition(state, SaraEvent.WAL_COMMIT) == SaraState.AUDITED.
        """
        verdict, sha256, raw = _resolve_observation_and_verdict(
            first,
            second,
            observation_sha256=observation_sha256,
            raw_output=raw_output,
        )

        if math.isnan(verdict.risk_score) or math.isinf(verdict.risk_score):
            raise ValueError("risk_score shall never be NaN or Inf")

        pre_state = state if state is not None else _pre_commit_state_for_verdict(verdict.verdict)

        def _commit(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO sara_tool_execution_logs
                    (execution_id, tool_name, observation_sha256, risk_score, verdict)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        verdict.execution_id,
                        verdict.tool_name,
                        sha256,
                        float(verdict.risk_score),
                        verdict.verdict.value,
                    ),
                )
                if verdict.verdict is VerdictKind.QUARANTINE_TOOL:
                    quarantine_id = derive_quarantine_id(verdict.execution_id)
                    reason = (
                        verdict.violation_reason
                        or "Quarantined by SARA runtime authorization gate"
                    )[:512]
                    conn.execute(
                        """
                        INSERT INTO sara_quarantine_payloads
                        (quarantine_id, execution_id, raw_output, violation_reason)
                        VALUES (?, ?, ?, ?)
                        """,
                        (quarantine_id, verdict.execution_id, raw, reason),
                    )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        self._execute_with_retry(_commit)
        return transition(pre_state, SaraEvent.WAL_COMMIT)

    def record_verdict(
        self,
        first: Any,
        second: Any = None,
        *,
        observation_sha256: Optional[str] = None,
        raw_output: Optional[str] = None,
        state: Optional[SaraState] = None,
    ) -> SaraState:
        """Alias for audit_commit."""
        return self.audit_commit(
            first,
            second,
            observation_sha256=observation_sha256,
            raw_output=raw_output,
            state=state,
        )

    def audit_commit_fail_closed(
        self,
        first: Any,
        second: Any = None,
        *,
        observation_sha256: Optional[str] = None,
        raw_output: Optional[str] = None,
        state: Optional[SaraState] = None,
    ) -> Tuple[AuthorizationVerdictDTO, SaraState]:
        """Attempt audit_commit with bounded retries; degrade fail-closed to QUARANTINE_TOOL on failure."""
        try:
            verdict, _, _ = _resolve_observation_and_verdict(
                first,
                second,
                observation_sha256=observation_sha256,
                raw_output=raw_output,
            )
            final_state = self.audit_commit(
                first,
                second,
                observation_sha256=observation_sha256,
                raw_output=raw_output,
                state=state,
            )
            return verdict, final_state
        except Exception as exc:
            from ctxfw.sara.gate import _extract_safe_execution_id, _extract_safe_tool_name

            exe_id = _extract_safe_execution_id(first)
            if exe_id == "EXE-0000failclosed" and second is not None:
                exe_id = _extract_safe_execution_id(second)
            t_name = _extract_safe_tool_name(first, second)
            reason = f"WAL audit sink fail-closed ({type(exc).__name__}): {exc}".strip()[:512]
            if not reason:
                reason = "WAL audit sink fail-closed: persistence fault"
            fallback = AuthorizationVerdictDTO(
                execution_id=exe_id,
                tool_name=t_name,
                verdict=VerdictKind.QUARANTINE_TOOL,
                risk_score=1.0,
                directives=(),
                violation_reason=reason,
            )
            return fallback, SaraState.REJECTED_INVALID

    def get_policy(self, policy_id: str) -> Optional[dict[str, Any]]:
        """Fetch an authorized policy row by policy_id."""

        def _query(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT policy_id, tool_name, policy_mask, created_at
                FROM sara_authorized_policies
                WHERE policy_id = ?
                """,
                (policy_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "policy_id": row[0],
                "tool_name": row[1],
                "policy_mask": row[2],
                "created_at": row[3],
            }

        return self._execute_with_retry(_query)

    def list_policies(self, tool_name: Optional[str] = None) -> list[dict[str, Any]]:
        """List authorized policies, optionally filtered by tool_name."""

        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            if tool_name is not None:
                cur = conn.execute(
                    """
                    SELECT policy_id, tool_name, policy_mask, created_at
                    FROM sara_authorized_policies
                    WHERE tool_name = ?
                    ORDER BY rowid ASC
                    """,
                    (tool_name,),
                )
            else:
                cur = conn.execute(
                    """
                    SELECT policy_id, tool_name, policy_mask, created_at
                    FROM sara_authorized_policies
                    ORDER BY rowid ASC
                    """
                )
            return [
                {
                    "policy_id": r[0],
                    "tool_name": r[1],
                    "policy_mask": r[2],
                    "created_at": r[3],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def get_execution_log(self, execution_id: str) -> Optional[dict[str, Any]]:
        """Fetch an execution log row by execution_id (never contains raw_output)."""

        def _query(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT execution_id, tool_name, observation_sha256, risk_score, verdict, created_at
                FROM sara_tool_execution_logs
                WHERE execution_id = ?
                """,
                (execution_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "execution_id": row[0],
                "tool_name": row[1],
                "observation_sha256": row[2],
                "risk_score": row[3],
                "verdict": row[4],
                "created_at": row[5],
            }

        return self._execute_with_retry(_query)

    get_log = get_execution_log

    def list_execution_logs(
        self,
        tool_name: Optional[str] = None,
        verdict: Optional[Union[VerdictKind, str]] = None,
    ) -> list[dict[str, Any]]:
        """List execution log rows ordered by insertion order."""
        verdict_val = verdict.value if isinstance(verdict, VerdictKind) else verdict

        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            clauses: list[str] = []
            params: list[Any] = []
            if tool_name is not None:
                clauses.append("tool_name = ?")
                params.append(tool_name)
            if verdict_val is not None:
                clauses.append("verdict = ?")
                params.append(verdict_val)
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            cur = conn.execute(
                f"""
                SELECT execution_id, tool_name, observation_sha256, risk_score, verdict, created_at
                FROM sara_tool_execution_logs
                {where_sql}
                ORDER BY rowid ASC
                """,
                tuple(params),
            )
            return [
                {
                    "execution_id": r[0],
                    "tool_name": r[1],
                    "observation_sha256": r[2],
                    "risk_score": r[3],
                    "verdict": r[4],
                    "created_at": r[5],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def get_quarantine_payload(self, identifier: str) -> Optional[dict[str, Any]]:
        """Fetch an isolated quarantine payload by execution_id or quarantine_id."""

        def _query(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT quarantine_id, execution_id, raw_output, violation_reason, isolated_at
                FROM sara_quarantine_payloads
                WHERE execution_id = ? OR quarantine_id = ?
                """,
                (identifier, identifier),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "quarantine_id": row[0],
                "execution_id": row[1],
                "raw_output": row[2],
                "violation_reason": row[3],
                "isolated_at": row[4],
            }

        return self._execute_with_retry(_query)

    get_quarantine = get_quarantine_payload

    def list_quarantine_payloads(self) -> list[dict[str, Any]]:
        """List all isolated quarantine payloads ordered by rowid."""

        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT quarantine_id, execution_id, raw_output, violation_reason, isolated_at
                FROM sara_quarantine_payloads
                ORDER BY rowid ASC
                """
            )
            return [
                {
                    "quarantine_id": r[0],
                    "execution_id": r[1],
                    "raw_output": r[2],
                    "violation_reason": r[3],
                    "isolated_at": r[4],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def delete_execution_log(self, execution_id: str) -> None:
        """Delete a parent execution log row (cascading to sara_quarantine_payloads if present)."""

        def _delete(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "DELETE FROM sara_tool_execution_logs WHERE execution_id = ?",
                    (execution_id,),
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

        self._execute_with_retry(_delete)

    def close(self) -> None:
        """Close the underlying SQLite connection if owned by this sink."""
        with self._lock:
            if self._owns_connection:
                self._conn.close()

    def __enter__(self) -> "AuditSink":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
