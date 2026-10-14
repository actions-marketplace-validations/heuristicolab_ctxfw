# manifest_hash: 11b623b097312b17d33c0ba6b7984b5a1954a133506e93dd813af794b22c0f0f
"""
Claude Rules Compiler :: Rules Store
====================================
SQLite WAL persistence for compiled rule manifests, guards, and enforcement logs.
Enforces the 6 relational DDL triggers and atomic manifest/guard persistence.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, TypeVar, Union

from ctxfw.rules import load_schema_sql
from ctxfw.rules.contracts import (
    INTENT_TO_PATTERN,
    CompiledAstGuardDTO,
    CompiledRuleManifestDTO,
    EnforcementVerdict,
    PatternType,
    RuleIntent,
)
from ctxfw.rules.enforcer import RulesEnforcer

__all__ = ["RulesStore"]

T = TypeVar("T")


class RulesStore:
    """Thread-safe SQLite WAL persistence store for compiled rules and audit logs."""

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
        conn.execute("PRAGMA synchronous = NORMAL")
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

    def persist_manifest(self, manifest: CompiledRuleManifestDTO) -> None:
        """Atomically persist a compiled rule manifest and its associated guards."""
        if not isinstance(manifest, CompiledRuleManifestDTO):
            raise TypeError(f"manifest must be CompiledRuleManifestDTO, got {type(manifest).__name__}")

        def _persist(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT 1 FROM compiled_rule_manifests WHERE manifest_id = ?",
                    (manifest.manifest_id,),
                )
                if cur.fetchone() is not None:
                    conn.execute("COMMIT")
                    return

                conn.execute(
                    """
                    INSERT INTO compiled_rule_manifests
                    (manifest_id, source_file_path, file_sha256, compiled_rules_count)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        manifest.manifest_id,
                        manifest.source.file_path,
                        manifest.source.sha256,
                        manifest.compiled_rules_count,
                    ),
                )
                for guard in manifest.guards:
                    conn.execute(
                        """
                        INSERT INTO compiled_ast_guards
                        (guard_id, manifest_id, rule_intent, target_expression)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            guard.guard_id,
                            manifest.manifest_id,
                            guard.rule_intent.value,
                            guard.target_symbol_or_path,
                        ),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        self._execute_with_retry(_persist)

    def enforce_and_log(
        self,
        guards: tuple[CompiledAstGuardDTO, ...],
        tool_call: str,
        seq: int,
    ) -> tuple[EnforcementVerdict, tuple[str, ...]]:
        """Evaluate tool_call against guards using RulesEnforcer and log verdict to rule_enforcement_logs."""
        verdict, matched_ids = RulesEnforcer.evaluate(guards, tool_call)

        def _log(conn: sqlite3.Connection) -> None:
            if not guards:
                return

            if verdict is EnforcementVerdict.BLOCKED and matched_ids:
                primary_guard = matched_ids[0]
            else:
                primary_guard = guards[0].guard_id

            # Verify that primary_guard exists in compiled_ast_guards before inserting FK
            cur = conn.execute(
                "SELECT 1 FROM compiled_ast_guards WHERE guard_id = ?",
                (primary_guard,),
            )
            if cur.fetchone() is None:
                return

            sanitized_call = (tool_call or " ")[:4096]
            digest = hashlib.sha256(f"{primary_guard}:{sanitized_call}:{seq}".encode("utf-8")).hexdigest()[:16]
            log_id = f"LOG-{digest}"

            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO rule_enforcement_logs
                    (log_id, guard_id, tool_call_attempted, verdict)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(log_id) DO NOTHING
                    """,
                    (log_id, primary_guard, sanitized_call, verdict.value),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        self._execute_with_retry(_log)
        return verdict, matched_ids

    def get_manifest(self, manifest_id: str) -> dict[str, Any] | None:
        """Fetch manifest row by ID."""
        def _query(conn: sqlite3.Connection) -> dict[str, Any] | None:
            cur = conn.execute(
                """
                SELECT manifest_id, source_file_path, file_sha256, compiled_rules_count, created_at
                FROM compiled_rule_manifests
                WHERE manifest_id = ?
                """,
                (manifest_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "manifest_id": row[0],
                "source_file_path": row[1],
                "file_sha256": row[2],
                "compiled_rules_count": row[3],
                "created_at": row[4],
            }

        return self._execute_with_retry(_query)

    def get_guards(self, manifest_id: str) -> list[dict[str, Any]]:
        """Fetch all guards associated with a manifest ID."""
        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT guard_id, manifest_id, rule_intent, target_expression, created_at
                FROM compiled_ast_guards
                WHERE manifest_id = ?
                ORDER BY rowid ASC
                """,
                (manifest_id,),
            )
            return [
                {
                    "guard_id": r[0],
                    "manifest_id": r[1],
                    "rule_intent": r[2],
                    "target_expression": r[3],
                    "created_at": r[4],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def get_logs(self, guard_id: str) -> list[dict[str, Any]]:
        """Fetch all enforcement log rows for a guard ID."""
        def _query(conn: sqlite3.Connection) -> list[dict[str, Any]]:
            cur = conn.execute(
                """
                SELECT log_id, guard_id, tool_call_attempted, verdict, created_at
                FROM rule_enforcement_logs
                WHERE guard_id = ?
                ORDER BY rowid ASC
                """,
                (guard_id,),
            )
            return [
                {
                    "log_id": r[0],
                    "guard_id": r[1],
                    "tool_call_attempted": r[2],
                    "verdict": r[3],
                    "created_at": r[4],
                }
                for r in cur.fetchall()
            ]

        return self._execute_with_retry(_query)

    def ensure_system_guard(self) -> CompiledAstGuardDTO:
        """Ensure a sealed system security guard exists for baseline traversal and policy enforcement."""
        from ctxfw.rules.compiler import RulesCompiler

        manifest, _, _ = RulesCompiler.compile_text(
            "CLAUDE.md", "- do not modify `system/security/traversal`\n"
        )
        if manifest is not None:
            self.persist_manifest(manifest)
            return manifest.guards[0]
        raise RuntimeError("Failed to compile system security guard")

    def get_all_guards(self) -> list[CompiledAstGuardDTO]:
        """Fetch all compiled guards across all manifests."""
        def _query(conn: sqlite3.Connection) -> list[CompiledAstGuardDTO]:
            cur = conn.execute(
                """
                SELECT guard_id, manifest_id, rule_intent, target_expression
                FROM compiled_ast_guards
                ORDER BY rowid ASC
                """
            )
            guards: list[CompiledAstGuardDTO] = []
            for r in cur.fetchall():
                try:
                    intent = RuleIntent(r[2])
                    gid = r[0]
                    rid = f"RULE-{gid[4:]}" if gid.startswith("GRD-") else f"RULE-{gid}"
                    guards.append(
                        CompiledAstGuardDTO(
                            guard_id=gid,
                            rule_id=rid,
                            pattern_type=INTENT_TO_PATTERN[intent],
                            target_symbol_or_path=r[3],
                            is_strict_deny=True,
                        )
                    )
                except Exception:
                    continue
            return guards

        return self._execute_with_retry(_query)

    def close(self) -> None:
        """Close connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "RulesStore":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
