# manifest_hash: 8f925c1e7c680c7af68e6f3daa48a5ac734923438762ed8836878a97508ce42e
"""
SARA Store :: Sovereign SQLite WAL Persistence & Quarantine Store
=================================================================
Provides SaraStore over SQLite WAL (schema.sql), inheriting all atomic
audit and quarantine capabilities of AuditSink and adding end-to-end
gate-to-WAL evaluation helpers.
"""
from __future__ import annotations

from typing import Any, Tuple

from ctxfw.sara.audit import (
    AuditSink,
    AuthorizedPolicyDTO,
    UntrustedObservationDTO,
    derive_quarantine_id,
)
from ctxfw.sara.contracts import (
    AuthorizationVerdictDTO,
    SaraEvent,
    SaraState,
    transition,
)
from ctxfw.sara.gate import RuntimeAuthorizationGate

__all__ = [
    "AuditSink",
    "AuthorizedPolicyDTO",
    "SaraStore",
    "UntrustedObservationDTO",
    "derive_quarantine_id",
]


class SaraStore(AuditSink):
    """Thread-safe SQLite WAL persistence store for SARA policies, logs, and quarantine payloads."""

    def authorize_and_record(
        self,
        observation: UntrustedObservationDTO,
        policy: AuthorizedPolicyDTO,
    ) -> Tuple[AuthorizationVerdictDTO, list[SaraState]]:
        """Evaluate observation through RuntimeAuthorizationGate and commit verdict to SQLite WAL."""
        verdict, trace = RuntimeAuthorizationGate.authorize_traced(observation, policy)
        audited_state = self.audit_commit(observation, verdict, state=trace[-1])
        trace.append(audited_state)
        return verdict, trace

    def authorize_and_record_fail_closed(
        self,
        observation: Any,
        policy: Any,
    ) -> Tuple[AuthorizationVerdictDTO, list[SaraState]]:
        """Evaluate observation and commit to WAL in fail-closed mode without raising exceptions."""
        verdict, trace = RuntimeAuthorizationGate.authorize_fail_closed(observation, policy)
        if trace and trace[-1] is SaraState.REJECTED_INVALID:
            return verdict, trace
        committed_verdict, final_state = self.audit_commit_fail_closed(
            observation, verdict, state=trace[-1] if trace else None
        )
        trace.append(final_state)
        return committed_verdict, trace

    def __enter__(self) -> "SaraStore":
        return self
