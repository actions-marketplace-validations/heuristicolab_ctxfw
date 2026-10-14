"""TraceKit store: exclusive SQLite WAL persistence for the hash-chained ledger (milestone 4.0-M1, P2).

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000 | 9 negative invariants
manifest_hash: 5a5339ac310d5ccd6e435f0652f6294ed641815fe5e2a541a6f95c06d35646e6
Sealed blueprint manifest_hash (TraceKit SIG-728856af9bd65ae0):
    7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c

Rules enforced here:
  * Exclusive database: only ``tracekit.db`` (or ``:memory:`` for tests). ``tokens.db``, ``telemetry.db``
    and any other file name are refused.
  * WAL, ``synchronous=NORMAL``, ``busy_timeout=5000``, ``foreign_keys=ON``.
  * The sealed DDL is applied as-is, then the store refuses to start unless exactly the 3 sealed tables
    and the 12 sealed triggers are present (the triggers, not this code, enforce append-only, contiguous
    sequence, chain link, monotonic time and the tamper latch; none of that logic is duplicated here).
  * One transaction per block. Writes run under the kernel's bounded retry (max 3 retries, backoff
    0.02/0.04/0.08 s, transient lock errors only). Exhaustion yields ``REJECTED_INVALID`` with the block
    quarantined in the returned outcome and nothing written. Any other ``OperationalError`` propagates.
  * Never UPDATE, never DELETE. Never prints. Timestamps are UTC-aware and come from the injected Clock.

Latency note: with ``busy_timeout=5000`` a contended write can block up to 5 s per attempt; callers on a
latency-sensitive path (``ctxfw mcp``) must invoke the store off the response path.
"""
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Mapping, Optional, Union

from ctxfw.audit.contracts import (
    ChainVerificationAuditDTO,
    HashChainedAuditBlockDTO,
    LedgerEvent,
    LedgerState,
    canonical_timestamp,
    derive_genesis_hash,
    derive_ledger_id,
    transition,
)
from ctxfw.audit.sealer import PreimageIntegrityError, capture_triad, seal_block
from ctxfw.audit.verifier import apply_latch, fail_closed_audit, verify_fail_closed
from ctxfw.kernel.clock import Clock, require_utc
from ctxfw.kernel.contracts import AuditEventDTO, AuditReceiptDTO
from ctxfw.kernel.failure import FailureClass, classify_failure_class
from ctxfw.kernel.retry import RetryExhausted, run_with_wal_retry

__all__ = [
    "AppendOutcome",
    "EXPECTED_TABLES",
    "EXPECTED_TRIGGER_COUNT",
    "LatchPersistenceError",
    "LedgerAppendRejected",
    "SchemaIntegrityError",
    "TRACEKIT_DB_NAME",
    "TraceKitStore",
    "resolve_tracekit_db_path",
]

TRACEKIT_DB_NAME = "tracekit.db"
TRACEKIT_DB_ENV = "CTXFW_TRACEKIT_DB"
MEMORY_DB = ":memory:"
EXPECTED_TRIGGER_COUNT = 12
EXPECTED_TABLES = frozenset(
    {"tracekit_sessions", "tracekit_audit_blocks", "tracekit_verification_events"}
)
BUSY_TIMEOUT_MS = 5000
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class SchemaIntegrityError(RuntimeError):
    """The database does not carry exactly the sealed tables/triggers (failure class SECURITY)."""


class LedgerAppendRejected(RuntimeError):
    """An append ended in ``REJECTED_INVALID``; the outcome carries the quarantined block."""

    def __init__(self, outcome: "AppendOutcome") -> None:
        super().__init__(f"{outcome.state.value} [{outcome.failure_class}]: {outcome.reason}")
        self.outcome = outcome


class LatchPersistenceError(RuntimeError):
    """A tampered verdict could not be persisted, so the latch is NOT active (fail-closed signal)."""

    def __init__(self, audit: ChainVerificationAuditDTO, cause: BaseException) -> None:
        super().__init__(f"tampered verdict not persisted: {cause}")
        self.audit = audit
        self.cause = cause


def _classify_integrity_error(exc: sqlite3.IntegrityError) -> FailureClass:
    msg = str(exc)
    if "prev_block_hash does not match" in msg or "immutable" in msg or "direct DELETE" in msg:
        return FailureClass.SECURITY
    if "CHECK constraint failed" in msg:
        return FailureClass.DETERMINISTIC
    return FailureClass.BUSINESS


@dataclass(frozen=True)
class AppendOutcome:
    state: LedgerState
    failure_class: Optional[FailureClass]
    block: Optional[HashChainedAuditBlockDTO]
    quarantined: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, LedgerState):
            raise ValueError("state must be a LedgerState")
        if self.failure_class is not None and not isinstance(self.failure_class, FailureClass):
            object.__setattr__(self, "failure_class", classify_failure_class(self.failure_class))
        if self.state is LedgerState.APPENDED:
            if self.block is None or self.failure_class is not None or self.quarantined:
                raise ValueError("an APPENDED outcome carries a block and no failure")
        elif self.state is LedgerState.REJECTED_INVALID:
            if self.failure_class is None or not self.quarantined:
                raise ValueError("a REJECTED_INVALID outcome carries a failure class and is quarantined")
        else:
            raise ValueError("append outcomes are APPENDED or REJECTED_INVALID only")

    @property
    def is_rejected(self) -> bool:
        return self.state is not LedgerState.APPENDED or self.quarantined


def resolve_tracekit_db_path(environ: Optional[Mapping[str, str]] = None) -> Path:
    """``CTXFW_TRACEKIT_DB`` override, else ``tracekit.db`` next to the canonical ``tokens.db``."""
    source = os.environ if environ is None else environ
    override = source.get(TRACEKIT_DB_ENV)
    if override:
        path = Path(override)
    else:
        from ctxfw.storage.cache import get_canonical_cache_path

        path = Path(get_canonical_cache_path()).parent / TRACEKIT_DB_NAME
    if path.name != TRACEKIT_DB_NAME:
        raise ValueError(f"the TraceKit database file must be named {TRACEKIT_DB_NAME}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


class TraceKitStore:
    """Exclusive handle to ``tracekit.db``. Thread-safe through one lock around a single connection."""

    def __init__(
        self,
        db_path: Union[str, Path],
        clock: Clock,
        *,
        sleep: Optional[Callable[[float], None]] = None,
    ) -> None:
        if not isinstance(clock, Clock):
            raise TypeError("clock must implement ctxfw.kernel.clock.Clock")
        target = str(db_path)
        if target != MEMORY_DB and Path(target).name != TRACEKIT_DB_NAME:
            raise ValueError(f"TraceKitStore opens only {TRACEKIT_DB_NAME} (or {MEMORY_DB}), got {Path(target).name!r}")
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.RLock()
        self._path = target
        self._conn = sqlite3.connect(target, timeout=10.0, isolation_level=None, check_same_thread=False)
        try:
            self._configure_and_validate()
        except BaseException:
            self._conn.close()
            raise

    # ------------------------------------------------------------------ lifecycle
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "TraceKitStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def db_path(self) -> str:
        return self._path

    # ------------------------------------------------------------------ schema
    def _configure_and_validate(self) -> None:
        from ctxfw.audit import load_schema_sql

        schema = load_schema_sql()
        expected_triggers = frozenset(re.findall(r"CREATE TRIGGER IF NOT EXISTS (\w+)", schema))
        if len(expected_triggers) != EXPECTED_TRIGGER_COUNT:
            raise SchemaIntegrityError("the sealed DDL no longer declares exactly 12 triggers")

        def init() -> None:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(schema)

        run_with_wal_retry(init, sleep=self._sleep)
        # the sealed script re-asserts ``foreign_keys = ON``; pin the connection pragmas again
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        self._conn.execute("PRAGMA foreign_keys=ON")
        if self._path != MEMORY_DB:
            mode = self._conn.execute("PRAGMA journal_mode").fetchone()[0]
            if str(mode).lower() != "wal":
                raise SchemaIntegrityError(f"WAL journal mode unavailable (got {mode!r})")
        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not EXPECTED_TABLES <= tables:
            raise SchemaIntegrityError(f"missing sealed tables: {sorted(EXPECTED_TABLES - tables)}")
        found = frozenset(r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'"))
        if found != expected_triggers or len(found) != EXPECTED_TRIGGER_COUNT:
            raise SchemaIntegrityError(
                f"expected exactly the 12 sealed triggers; missing={sorted(expected_triggers - found)} "
                f"unexpected={sorted(found - expected_triggers)}"
            )

    def trigger_names(self) -> List[str]:
        with self._lock:
            return sorted(r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'"))

    def pragma(self, name: str) -> object:
        """Read-only view of a connection pragma (diagnostics/tests). ``name`` is an identifier."""
        if re.fullmatch(r"[a-z_]+", name) is None:
            raise ValueError("invalid pragma name")
        with self._lock:
            return self._conn.execute(f"PRAGMA {name}").fetchone()[0]

    # ------------------------------------------------------------------ append
    def _append_txn(
        self,
        session_id: str,
        intent_digest: str,
        reasoning_digest: str,
        action_digest: str,
        timestamp_utc: datetime,
        holder: dict,
    ) -> HashChainedAuditBlockDTO:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT genesis_hash FROM tracekit_sessions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if row is None:
                    genesis = derive_genesis_hash(session_id)
                    self._conn.execute(
                        "INSERT INTO tracekit_sessions (session_id, genesis_hash, created_at) VALUES (?, ?, ?)",
                        (session_id, genesis, canonical_timestamp(timestamp_utc)),
                    )
                else:
                    genesis = row[0]
                count = self._conn.execute(
                    "SELECT COUNT(*) FROM tracekit_audit_blocks WHERE session_id = ?", (session_id,)
                ).fetchone()[0]
                prev = genesis
                if count > 0:
                    prev_row = self._conn.execute(
                        "SELECT current_block_hash FROM tracekit_audit_blocks "
                        "WHERE session_id = ? AND block_seq = ?",
                        (session_id, count - 1),
                    ).fetchone()
                    if prev_row is not None:
                        prev = prev_row[0]
                block = seal_block(
                    session_id, count, prev, intent_digest, reasoning_digest, action_digest, timestamp_utc
                )
                holder["block"] = block
                self._conn.execute(
                    "INSERT INTO tracekit_audit_blocks (block_id, session_id, block_seq, prev_block_hash, "
                    "current_block_hash, intent_digest, reasoning_digest, action_digest, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        block.block_id,
                        block.session_id,
                        block.block_seq,
                        block.prev_block_hash,
                        block.current_block_hash,
                        block.intent_digest,
                        block.reasoning_digest,
                        block.action_digest,
                        canonical_timestamp(block.timestamp_utc),
                    ),
                )
                self._conn.execute("COMMIT")
                return block
            except BaseException:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass  # no open transaction (e.g. BEGIN itself was refused)
                raise

    def append_digests(
        self,
        session_id: str,
        intent_digest: str,
        reasoning_digest: str,
        action_digest: str,
        timestamp_utc: datetime,
    ) -> AppendOutcome:
        """Seal and persist one block. Never raises for ledger-domain failures: returns the outcome."""
        holder: dict = {}
        try:
            require_utc(timestamp_utc)
            block = run_with_wal_retry(
                lambda: self._append_txn(
                    session_id, intent_digest, reasoning_digest, action_digest, timestamp_utc, holder
                ),
                sleep=self._sleep,
            )
        except RetryExhausted as exc:
            return self._rejected(
                FailureClass.TRANSIENT, holder, LedgerEvent.WAL_RETRY_EXHAUSTED, f"WAL retries exhausted: {exc.last_error}"
            )
        except PreimageIntegrityError as exc:
            return self._rejected(FailureClass.SECURITY, holder, LedgerEvent.VALIDATION_FAIL, str(exc))
        except (ValueError, TypeError) as exc:  # includes pydantic ValidationError and type errors
            return self._rejected(FailureClass.DETERMINISTIC, holder, LedgerEvent.VALIDATION_FAIL, str(exc))
        except sqlite3.IntegrityError as exc:  # ABORT raised by a sealed trigger / CHECK
            return self._rejected(_classify_integrity_error(exc), holder, LedgerEvent.VALIDATION_FAIL, str(exc))
        state = transition(LedgerState.SEALED, LedgerEvent.WAL_COMMIT)
        return AppendOutcome(state, None, block, False, "appended")

    @staticmethod
    def _rejected(
        failure: FailureClass, holder: dict, event: LedgerEvent, reason: str
    ) -> AppendOutcome:
        state = transition(LedgerState.SEALED, event)
        return AppendOutcome(state, failure, holder.get("block"), True, reason)

    def append_event_outcome(self, event: AuditEventDTO) -> AppendOutcome:
        if not isinstance(event, AuditEventDTO):
            raise TypeError("event must be an AuditEventDTO")
        return self.append_digests(
            event.session_id, event.intent_sha256, event.reasoning_sha256, event.payload_sha256, event.timestamp_utc
        )

    def append(self, event: AuditEventDTO) -> AuditReceiptDTO:
        """Kernel ``AuditPort`` implementation. Raises ``LedgerAppendRejected`` on a rejected append."""
        outcome = self.append_event_outcome(event)
        if outcome.state is not LedgerState.APPENDED or outcome.block is None:
            raise LedgerAppendRejected(outcome)
        return AuditReceiptDTO(
            session_id=outcome.block.session_id,
            block_seq=outcome.block.block_seq,
            block_hash=outcome.block.current_block_hash,
        )

    def record_step(
        self, session_id: str, user_prompt: str, plan_summary: str, tool_or_file: str, payload: str
    ) -> AppendOutcome:
        """Capture the Intent-Reasoning-Action triad from raw text and append it, stamped by the Clock."""
        try:
            count = self._block_count(session_id)
            intent, reasoning, action = capture_triad(
                session_id, count, user_prompt, plan_summary, tool_or_file, payload
            )
        except (ValueError, TypeError) as exc:  # includes pydantic ValidationError and non-str inputs
            return self._rejected(FailureClass.DETERMINISTIC, {}, LedgerEvent.VALIDATION_FAIL, str(exc))
        return self.append_digests(
            session_id, intent.intent_sha256, reasoning.reasoning_sha256, action.payload_sha256, self._clock.now()
        )

    # ------------------------------------------------------------------ read / verify
    def _block_count(self, session_id: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM tracekit_audit_blocks WHERE session_id = ?", (session_id,)
            ).fetchone()[0]

    def load_blocks(self, session_id: str) -> List[HashChainedAuditBlockDTO]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT block_id, session_id, block_seq, prev_block_hash, current_block_hash, intent_digest, "
                "reasoning_digest, action_digest, created_at FROM tracekit_audit_blocks "
                "WHERE session_id = ? ORDER BY block_seq",
                (session_id,),
            ).fetchall()
        return [
            HashChainedAuditBlockDTO(
                block_id=r[0],
                session_id=r[1],
                block_seq=r[2],
                prev_block_hash=r[3],
                current_block_hash=r[4],
                intent_digest=r[5],
                reasoning_digest=r[6],
                action_digest=r[7],
                timestamp_utc=datetime.strptime(r[8], _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc),
            )
            for r in rows
        ]

    def latched_broken_seq(self, session_id: str) -> Optional[int]:
        """``broken_seq`` of the earliest persisted tampered verdict, or ``None`` if not latched."""
        with self._lock:
            row = self._conn.execute(
                "SELECT broken_seq FROM tracekit_verification_events "
                "WHERE session_id = ? AND is_tampered = 1 ORDER BY rowid LIMIT 1",
                (session_id,),
            ).fetchone()
        return None if row is None else row[0]

    def _persist_verdict_txn(self, audit: ChainVerificationAuditDTO) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                seq = self._conn.execute(
                    "SELECT COUNT(*) FROM tracekit_verification_events WHERE session_id = ?",
                    (audit.session_id,),
                ).fetchone()[0]
                self._conn.execute(
                    "INSERT INTO tracekit_verification_events (event_id, session_id, is_tampered, broken_seq, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        derive_ledger_id("EVT-", audit.session_id, seq),
                        audit.session_id,
                        1 if audit.is_tampered else 0,
                        audit.broken_block_seq,
                        canonical_timestamp(audit.verified_at),
                    ),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def verify_session(self, session_id: str) -> ChainVerificationAuditDTO:
        """Audit a stored chain and persist the verdict; a tampered verdict activates the latch.

        Never reports a latched session as clean. Raises ``LatchPersistenceError`` if a verdict that must
        latch could not be written (the audit is attached to the exception, never silently dropped).
        """
        verified_at = require_utc(self._clock.now())
        with self._lock:
            session = self._conn.execute(
                "SELECT genesis_hash FROM tracekit_sessions WHERE session_id = ?", (session_id,)
            ).fetchone() if isinstance(session_id, str) else None
            if session is None:
                return fail_closed_audit(session_id, verified_at)  # unknown session: reported, nothing to latch
            try:
                blocks = self.load_blocks(session_id)
            except ValueError:  # malformed stored row (offline edit): fail closed
                audit = fail_closed_audit(session_id, verified_at)
            else:
                audit = verify_fail_closed(session_id, session[0], blocks, verified_at)
            audit = apply_latch(audit, self.latched_broken_seq(session_id))
            try:
                run_with_wal_retry(lambda: self._persist_verdict_txn(audit), sleep=self._sleep)
            except (sqlite3.IntegrityError, RetryExhausted) as exc:
                if audit.is_tampered:
                    raise LatchPersistenceError(audit, exc) from exc
                raise
            return audit
