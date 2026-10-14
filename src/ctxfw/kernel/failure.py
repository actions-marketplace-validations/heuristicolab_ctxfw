"""Canonical failure taxonomy of the Sovereign Pentad kernel.

CTXFW Axiomatic Gateway: status VERIFIED | ACI 1.0000
manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3

Every vendored blueprint defines its own ``FailureClass`` (same four members, separate enum
types) and those files are byte-for-byte sealed, so they cannot be unified in place. This module
is the single canonical enum plus a **strict** adapter: anything that is not exactly one of the
four class names is routed to ``SECURITY`` (fail-closed), never to a benign class.
"""
from enum import Enum

__all__ = ["FailureClass", "classify_failure_class"]


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DETERMINISTIC = "DETERMINISTIC"
    BUSINESS = "BUSINESS"
    SECURITY = "SECURITY"


_BY_NAME = {member.value: member for member in FailureClass}


def classify_failure_class(value: object) -> FailureClass:
    """Total, side-effect-free mapping into the canonical taxonomy.

    Accepts a canonical member, a blueprint ``FailureClass`` member (any ``str`` enum whose value is
    an exact class name) or the exact upper-case class name as ``str``. Matching is exact: no case
    folding, no trimming, no coercion. Everything else (including ``None``, ``bytes``, ``bool``)
    is an unknown class and maps to ``SECURITY``.
    """
    if isinstance(value, FailureClass):
        return value
    raw = value.value if isinstance(value, Enum) else value
    if type(raw) is str:  # noqa: E721 -- exact str only; subclasses (e.g. str enums) were unwrapped above
        member = _BY_NAME.get(raw)
        if member is not None:
            return member
    return FailureClass.SECURITY
