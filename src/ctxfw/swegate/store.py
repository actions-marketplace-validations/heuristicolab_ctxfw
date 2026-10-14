# manifest_hash: ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
"""
SWE-Gate Transactional SQLite WAL Persistence Store (M4-P2)
===========================================================
Signal   : SIG-673052a2a791ec2b
Proposal : PROP-673052a2a791ec2b-H1
Horizon  : HORIZON_1
M4-P2 manifest_hash:
    ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
Sealed blueprint manifest_hash (VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f
Subagent attestation manifest_hash (VERIFIED, ACI 1.0000):
    b043387c0db2235d6cd63145a1def598a6975ead7d2cd4c9560928b9c14a0145

Append-only SQLite WAL persistence for SWE-Gate repositories, patch evaluations,
and architectural violation findings with bounded exponential backoff retry.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from . import load_schema_sql
from .contracts import (
    WAL_RETRY_ATTEMPTS_MAX,
    GateEvent,
    GateState,
    GateVerdict,
    PatchInspectionAuditDTO,
    PatchMetadataDTO,
    derive_gate_id,
    split_violation,
    transition,
)
from .gate import evaluate_patch

__all__ = [
    "SweGateStore",
    "persist_evaluation",
    "persist_with_retry",
]


def persist_evaluation(
    conn: sqlite3.Connection,
    repo_id: str,
    meta: PatchMetadataDTO,
    audit: PatchInspectionAuditDTO,
) -> str:
    """Persist an evaluation and its violation findings onto conn; return evaluation_id."""
    seq = conn.execute(
        "SELECT COUNT(*) FROM swe_gate_patch_evaluations WHERE repo_id = ? AND commit_sha = ?",
        (repo_id, meta.commit_sha),
    ).fetchone()[0]
    evaluation_id = derive_gate_id("EVL-", repo_id, meta.commit_sha, seq)
    conn.execute(
        "INSERT INTO swe_gate_patch_evaluations "
        "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            evaluation_id,
            repo_id,
            meta.commit_sha,
            1 if audit.is_functional_passed else 0,
            audit.gate_verdict.value,
            len(audit.architectural_violations),
        ),
    )
    for index, entry in enumerate(audit.architectural_violations):
        vtype, location = split_violation(entry)
        violation_id = derive_gate_id("VIO-", evaluation_id, index)
        conn.execute(
            "INSERT INTO swe_gate_violation_findings "
            "(violation_id, evaluation_id, violation_type, symbol_or_file) "
            "VALUES (?, ?, ?, ?)",
            (violation_id, evaluation_id, vtype.value, location),
        )
    return evaluation_id


def persist_with_retry(
    operation: Callable[[], Any],
    sleep: Callable[[float], None],
    decided_state: GateState,
    attempts: int = WAL_RETRY_ATTEMPTS_MAX,
    base: float = 0.01,
) -> Tuple[GateState, List[float]]:
    """Execute a WAL persistence operation with bounded exponential backoff."""
    naps: List[float] = []
    for attempt in range(1, attempts + 1):
        try:
            operation()
            return transition(decided_state, GateEvent.WAL_COMMIT), naps
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise
            nap = base * 2**attempt
            naps.append(nap)
            sleep(nap)
    return transition(decided_state, GateEvent.WAL_RETRY_EXHAUSTED), naps


class SweGateStore:
    """Thread-safe SQLite WAL persistence store for SWE-Gate evaluations and violations."""

    def __init__(
        self,
        db_path: Union[str, Path, sqlite3.Connection] = ":memory:",
    ) -> None:
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

    def init_db(self) -> None:
        """Idempotently initialize the sealed SWE-Gate relational schema and triggers."""
        with self._lock:
            self._conn.executescript(load_schema_sql())
            self._configure_connection(self._conn)

    def register_repository(
        self,
        repo_name: str,
        repo_id: Optional[str] = None,
    ) -> str:
        """Register a repository in swe_gate_repositories or return existing repo_id if identical."""
        if not isinstance(repo_name, str) or (
            repo_id is not None and not isinstance(repo_id, str)
        ):
            raise sqlite3.IntegrityError("repo_name and repo_id must be str")
        resolved_id = repo_id if repo_id is not None else derive_gate_id("REPO-", repo_name)
        with self._lock:
            started_tx = False
            if not self._conn.in_transaction:
                self._conn.execute("BEGIN IMMEDIATE")
                started_tx = True
            try:
                row = self._conn.execute(
                    "SELECT repo_name FROM swe_gate_repositories WHERE repo_id = ?",
                    (resolved_id,),
                ).fetchone()
                if row is not None:
                    if row[0] != repo_name:
                        raise sqlite3.IntegrityError(
                            f"Repository {resolved_id} already registered with name {row[0]!r}"
                        )
                    if started_tx and self._conn.in_transaction:
                        self._conn.commit()
                    return resolved_id
                self._conn.execute(
                    "INSERT INTO swe_gate_repositories (repo_id, repo_name) VALUES (?, ?)",
                    (resolved_id, repo_name),
                )
                if started_tx:
                    self._conn.commit()
                return resolved_id
            except BaseException:
                if started_tx and self._conn.in_transaction:
                    self._conn.rollback()
                raise

    def record_evaluation(
        self,
        repo_id: str,
        meta: PatchMetadataDTO,
        audit: PatchInspectionAuditDTO,
        decided_state: Optional[GateState] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Tuple[Optional[str], GateState, List[float]]:
        """Persist a patch evaluation inside an atomic WAL transaction with retry."""
        resolved_state = (
            decided_state
            if decided_state is not None
            else (
                GateState.DECIDED_PASS
                if audit.gate_verdict is GateVerdict.ALLOW_MERGE
                else GateState.DECIDED_REJECT
            )
        )
        if resolved_state not in (GateState.DECIDED_PASS, GateState.DECIDED_REJECT):
            return None, transition(resolved_state, GateEvent.VALIDATION_FAIL), []

        eval_id_holder: List[str] = []

        def _op() -> None:
            with self._lock:
                started_tx = False
                if not self._conn.in_transaction:
                    self._conn.execute("BEGIN IMMEDIATE")
                    started_tx = True
                try:
                    ev_id = persist_evaluation(self._conn, repo_id, meta, audit)
                    if started_tx:
                        self._conn.commit()
                    eval_id_holder.append(ev_id)
                except BaseException:
                    if started_tx and self._conn.in_transaction:
                        self._conn.rollback()
                    raise

        final_state, naps = persist_with_retry(_op, sleep, resolved_state)
        if final_state is GateState.REJECTED_INVALID or not eval_id_holder:
            return None, final_state, naps
        return eval_id_holder[-1], final_state, naps

    def evaluate_and_record(
        self,
        repo_id: str,
        meta: Any,
        functional: Any,
        rule: Any,
        diff_text: Any,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Tuple[PatchInspectionAuditDTO, Optional[str], List[GateState]]:
        """Evaluate a patch through the gate and persist its audit outcome if valid."""
        audit, trace = evaluate_patch(meta, functional, rule, diff_text)
        if trace and trace[-1] is GateState.REJECTED_INVALID:
            return audit, None, trace
        eval_id, final_state, _naps = self.record_evaluation(
            repo_id,
            meta,
            audit,
            decided_state=trace[-1],
            sleep=sleep,
        )
        trace.append(final_state)
        return audit, eval_id, trace

    def get_evaluation(self, evaluation_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a persisted patch evaluation record by evaluation_id."""
        with self._lock:
            row = self._conn.execute(
                "SELECT evaluation_id, repo_id, commit_sha, functional_passed, "
                "gate_verdict, violations_count, created_at "
                "FROM swe_gate_patch_evaluations WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "evaluation_id": row[0],
                "repo_id": row[1],
                "commit_sha": row[2],
                "functional_passed": bool(row[3]),
                "gate_verdict": row[4],
                "violations_count": row[5],
                "created_at": row[6],
            }

    def get_violations(self, evaluation_id: str) -> List[Dict[str, Any]]:
        """Fetch all persisted violation findings for an evaluation_id ordered by insertion."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT violation_id, evaluation_id, violation_type, symbol_or_file, created_at "
                "FROM swe_gate_violation_findings WHERE evaluation_id = ? ORDER BY rowid ASC",
                (evaluation_id,),
            ).fetchall()
            return [
                {
                    "violation_id": r[0],
                    "evaluation_id": r[1],
                    "violation_type": r[2],
                    "symbol_or_file": r[3],
                    "created_at": r[4],
                }
                for r in rows
            ]

    def close(self) -> None:
        """Close the underlying SQLite connection if owned by this store."""
        with self._lock:
            if self._owns_connection:
                self._conn.close()

    def __enter__(self) -> "SweGateStore":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
