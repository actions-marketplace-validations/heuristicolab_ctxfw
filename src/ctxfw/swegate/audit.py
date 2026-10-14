# manifest_hash: ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
"""
SWE-Gate Audit Sink Facade (M4-P2)
==================================
Signal   : SIG-673052a2a791ec2b
Proposal : PROP-673052a2a791ec2b-H1
Horizon  : HORIZON_1
M4-P2 manifest_hash:
    ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
Sealed blueprint manifest_hash (VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f
Subagent attestation manifest_hash (VERIFIED, ACI 1.0000):
    b043387c0db2235d6cd63145a1def598a6975ead7d2cd4c9560928b9c14a0145

Re-exports SweGateStore, persist_evaluation, and persist_with_retry, and
provides SweGateAuditSink for symmetry with ctxfw.sara.audit.
"""
from __future__ import annotations

from .store import SweGateStore, persist_evaluation, persist_with_retry

SweGateAuditSink = SweGateStore

__all__ = [
    "SweGateAuditSink",
    "SweGateStore",
    "persist_evaluation",
    "persist_with_retry",
]
