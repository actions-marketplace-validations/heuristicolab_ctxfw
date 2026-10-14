# manifest_hash: ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
"""
SWE-Gate Fail-Closed CI Verification Gate (M4-P2)
=================================================
Signal   : SIG-673052a2a791ec2b
Proposal : PROP-673052a2a791ec2b-H1
Horizon  : HORIZON_1
M4-P2 manifest_hash:
    ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
Sealed blueprint manifest_hash (VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f
Subagent attestation manifest_hash (VERIFIED, ACI 1.0000):
    b043387c0db2235d6cd63145a1def598a6975ead7d2cd4c9560928b9c14a0145

Deterministic fail-closed CI verification gate driving the total FSM
delta(S, E) from RECEIVED through DECIDED_PASS / DECIDED_REJECT or
collapsing to REJECTED_INVALID with INVALID_INPUT|patch on any malformed input.
"""
from __future__ import annotations

from typing import Any, List, Tuple

from .contracts import (
    FunctionalTestResultDTO,
    FunctionalVerdict,
    GateEvent,
    GateState,
    GateVerdict,
    PatchInspectionAuditDTO,
    PatchMetadataDTO,
    ViolationType,
    decide_gate_verdict,
    format_violation,
    transition,
)
from .inspector import SweGateInspector

__all__ = [
    "SweGateVerifier",
    "evaluate_patch",
]


def evaluate_patch(
    meta: Any,
    functional: Any,
    rule: Any,
    diff_text: Any,
) -> Tuple[PatchInspectionAuditDTO, List[GateState]]:
    """Evaluate a patch fail-closed and return (PatchInspectionAuditDTO, FSM trace)."""
    state = GateState.RECEIVED
    trace: List[GateState] = [state]
    passed = (
        isinstance(functional, FunctionalTestResultDTO)
        and functional.functional_verdict is FunctionalVerdict.PASSED
    )
    try:
        if not isinstance(meta, PatchMetadataDTO):
            raise ValueError("VALIDATION_FAIL")
        state = transition(state, GateEvent.PATCH_OK)
        trace.append(state)

        if not isinstance(functional, FunctionalTestResultDTO):
            raise ValueError("VALIDATION_FAIL")
        state = transition(state, GateEvent.REPORT_OK)
        trace.append(state)

        delta, violations = SweGateInspector.inspect(meta, rule, diff_text)
        state = transition(state, GateEvent.INSPECT_OK)
        trace.append(state)

        verdict = decide_gate_verdict(passed, violations)
        event = (
            GateEvent.CONSTRAINTS_MET
            if verdict is GateVerdict.ALLOW_MERGE
            else GateEvent.CONSTRAINTS_VIOLATED
        )
        state = transition(state, event)
        trace.append(state)

        return (
            PatchInspectionAuditDTO(
                is_functional_passed=passed,
                cyclomatic_delta=delta,
                architectural_violations=violations,
                gate_verdict=verdict,
            ),
            trace,
        )
    except (ValueError, TypeError):
        trace.append(transition(state, GateEvent.VALIDATION_FAIL))
        return (
            PatchInspectionAuditDTO(
                is_functional_passed=passed,
                cyclomatic_delta=0,
                architectural_violations=(
                    format_violation(ViolationType.INVALID_INPUT, "patch"),
                ),
                gate_verdict=GateVerdict.REJECT_ARCHITECTURAL_VIOLATION,
            ),
            trace,
        )


class SweGateVerifier:
    """Fail-closed CI verification gate evaluating patches against architectural constraints."""

    @staticmethod
    def evaluate(
        meta: Any,
        functional: Any,
        rule: Any,
        diff_text: Any,
    ) -> PatchInspectionAuditDTO:
        """Evaluate a patch and return the immutable PatchInspectionAuditDTO."""
        audit, _trace = evaluate_patch(meta, functional, rule, diff_text)
        return audit

    @staticmethod
    def evaluate_traced(
        meta: Any,
        functional: Any,
        rule: Any,
        diff_text: Any,
    ) -> Tuple[PatchInspectionAuditDTO, List[GateState]]:
        """Evaluate a patch and return (PatchInspectionAuditDTO, FSM state trace)."""
        return evaluate_patch(meta, functional, rule, diff_text)

    @staticmethod
    def evaluate_fail_closed(
        meta: Any,
        functional: Any,
        rule: Any,
        diff_text: Any,
    ) -> Tuple[PatchInspectionAuditDTO, List[GateState]]:
        """Alias for evaluate_patch (always fail-closed)."""
        return evaluate_patch(meta, functional, rule, diff_text)
