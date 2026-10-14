"""
SWE-GATE CI VERIFIER :: 2_pydantic_contracts.py
===============================================
Signal   : SIG-673052a2a791ec2b
Proposal : PROP-673052a2a791ec2b-H1
Horizon  : HORIZON_1
Source   : arXiv 2609.04167v1 -- "SWE-Gate: Passing Functional Tests Is Not Enough for Software
           Engineering Agents"
manifest_hash (CTXFW evaluate_spec_axioms, status VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f

Immutable Pydantic v2 contracts, total FSM, failure taxonomy and bound validators for a CI gate
that denies the merge of an agent patch that passes the functional tests but violates the
architectural review constraints.

Verdict names. The CI gate reports PASS_GATE / REJECT_NON_FUNCTIONAL_REGRESSION (FSM terminal
states); the persisted audit verdict is ALLOW_MERGE / REJECT_ARCHITECTURAL_VIOLATION. The mapping
is GATE_VERDICT_TO_TERMINAL. A functional failure with zero architectural findings is persisted as
REJECT_ARCHITECTURAL_VIOLATION because no third persisted verdict exists.

Negative invariants enforced by this module
-------------------------------------------
1. A DTO shall never be mutated after construction (frozen=True) and shall never accept an
   undeclared attribute (extra="forbid").
2. A commit sha shall never be accepted unless it is exactly 40 lowercase hex characters.
3. A patch shall never be accepted with diff_size_bytes outside [1, 1048576] (empty rejected).
4. ALLOW_MERGE shall never be produced when functional tests failed or any architectural
   violation was recorded.
5. transition(S, E) shall never raise: every (state, event) pair maps to a state and every
   unknown pair maps to REJECTED_INVALID (fail-closed); terminal states are absorbing.
6. A functional verdict shall never contradict its counters: PASSED requires tests_failed == 0
   and tests_passed >= 1.
7. A violation entry shall never use a type outside the closed ViolationType set or carry control
   characters; a violation tuple shall never exceed 256 entries.
8. The contracts shall never use a wall clock, randomness, network or floating point.
"""

import hashlib
import re
from enum import Enum
from types import MappingProxyType
from typing import Annotated, Mapping, Tuple

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# ----------------------------------------------------------------------------
# Closed numeric bounds (single source of truth shared with 3_schema_ddl.sql)
# ----------------------------------------------------------------------------
COMMIT_SHA_LEN: int = 40
COMMIT_SHA_PATTERN: str = r"^[0-9a-f]{40}$"
PR_ID_MIN: int = 1
PR_ID_MAX: int = 2_147_483_647
DIFF_SIZE_MIN: int = 1
DIFF_SIZE_MAX: int = 1_048_576
DIFF_LINES_MAX: int = 20_000
TESTS_COUNT_MIN: int = 0
TESTS_COUNT_MAX: int = 1_000_000
MAX_CYCLOMATIC_DELTA_MIN: int = 0
MAX_CYCLOMATIC_DELTA_MAX: int = 10_000
CYCLOMATIC_DELTA_MIN: int = -1_000_000
CYCLOMATIC_DELTA_MAX: int = 1_000_000
DISALLOWED_MODULES_MAX: int = 64
MODULE_NAME_MAX: int = 128
VIOLATIONS_MAX: int = 256
VIOLATION_ENTRY_MAX: int = 500
VIOLATION_LOCATION_MAX: int = 480
WAL_RETRY_ATTEMPTS_MAX: int = 3
INSPECTION_LATENCY_BUDGET_MS: float = 5.0

REPO_ID_PATTERN: str = r"^REPO-[A-Za-z0-9_-]{4,64}$"
EVALUATION_ID_PATTERN: str = r"^EVL-[A-Za-z0-9_-]{4,64}$"
VIOLATION_ID_PATTERN: str = r"^VIO-[A-Za-z0-9_-]{4,64}$"
RULE_ID_PATTERN: str = r"^RULE-[A-Za-z0-9_-]{4,64}$"
MODULE_NAME_PATTERN: str = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
VIOLATION_ENTRY_PATTERN: str = r"^[A-Z_]{3,32}\|[^\x00-\x1f\x7f]{1,480}$"

_MODULE_RE = re.compile(MODULE_NAME_PATTERN)
_VIOLATION_RE = re.compile(VIOLATION_ENTRY_PATTERN)
_ID_PREFIXES = frozenset({"REPO-", "EVL-", "VIO-", "RULE-"})


# ----------------------------------------------------------------------------
# Enumerations
# ----------------------------------------------------------------------------
class AuthorKind(str, Enum):
    HUMAN = "HUMAN"
    AGENT = "AGENT"


class FunctionalVerdict(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class GateVerdict(str, Enum):
    ALLOW_MERGE = "ALLOW_MERGE"
    REJECT_ARCHITECTURAL_VIOLATION = "REJECT_ARCHITECTURAL_VIOLATION"


class ViolationType(str, Enum):
    TYPE_IGNORE = "TYPE_IGNORE"
    DISALLOWED_IMPORT = "DISALLOWED_IMPORT"
    CYCLOMATIC_DELTA = "CYCLOMATIC_DELTA"
    INVALID_INPUT = "INVALID_INPUT"


class FailureClass(str, Enum):
    TRANSIENT = "TRANSIENT"
    DETERMINISTIC = "DETERMINISTIC"
    BUSINESS = "BUSINESS"
    SECURITY = "SECURITY"


class GateState(str, Enum):
    RECEIVED = "RECEIVED"
    PATCH_INGESTED = "PATCH_INGESTED"
    REPORT_INGESTED = "REPORT_INGESTED"
    INSPECTED = "INSPECTED"
    DECIDED_PASS = "DECIDED_PASS"
    DECIDED_REJECT = "DECIDED_REJECT"
    PASS_GATE = "PASS_GATE"
    REJECT_NON_FUNCTIONAL_REGRESSION = "REJECT_NON_FUNCTIONAL_REGRESSION"
    REJECTED_INVALID = "REJECTED_INVALID"


class GateEvent(str, Enum):
    PATCH_OK = "PATCH_OK"
    REPORT_OK = "REPORT_OK"
    INSPECT_OK = "INSPECT_OK"
    CONSTRAINTS_MET = "CONSTRAINTS_MET"
    CONSTRAINTS_VIOLATED = "CONSTRAINTS_VIOLATED"
    WAL_COMMIT = "WAL_COMMIT"
    WAL_RETRY_EXHAUSTED = "WAL_RETRY_EXHAUSTED"
    VALIDATION_FAIL = "VALIDATION_FAIL"


TERMINAL_STATES: frozenset = frozenset(
    {
        GateState.PASS_GATE,
        GateState.REJECT_NON_FUNCTIONAL_REGRESSION,
        GateState.REJECTED_INVALID,
    }
)

_S = GateState
_E = GateEvent

# delta(S, E) -- exactly 13 explicit transitions; every other pair is fail-closed.
TRANSITION_TABLE: Mapping[Tuple[GateState, GateEvent], GateState] = MappingProxyType(
    {
        (_S.RECEIVED, _E.PATCH_OK): _S.PATCH_INGESTED,
        (_S.RECEIVED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.PATCH_INGESTED, _E.REPORT_OK): _S.REPORT_INGESTED,
        (_S.PATCH_INGESTED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.REPORT_INGESTED, _E.INSPECT_OK): _S.INSPECTED,
        (_S.REPORT_INGESTED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.INSPECTED, _E.CONSTRAINTS_MET): _S.DECIDED_PASS,
        (_S.INSPECTED, _E.CONSTRAINTS_VIOLATED): _S.DECIDED_REJECT,
        (_S.INSPECTED, _E.VALIDATION_FAIL): _S.REJECTED_INVALID,
        (_S.DECIDED_PASS, _E.WAL_COMMIT): _S.PASS_GATE,
        (_S.DECIDED_PASS, _E.WAL_RETRY_EXHAUSTED): _S.REJECTED_INVALID,
        (_S.DECIDED_REJECT, _E.WAL_COMMIT): _S.REJECT_NON_FUNCTIONAL_REGRESSION,
        (_S.DECIDED_REJECT, _E.WAL_RETRY_EXHAUSTED): _S.REJECTED_INVALID,
    }
)

# Persisted audit verdict -> terminal CI state reached after WAL_COMMIT.
GATE_VERDICT_TO_TERMINAL: Mapping[GateVerdict, GateState] = MappingProxyType(
    {
        GateVerdict.ALLOW_MERGE: GateState.PASS_GATE,
        GateVerdict.REJECT_ARCHITECTURAL_VIOLATION: GateState.REJECT_NON_FUNCTIONAL_REGRESSION,
    }
)

# Failure taxonomy: every failure code is routed to exactly one of the four classes.
FAILURE_ROUTING: Mapping[str, FailureClass] = MappingProxyType(
    {
        "WAL_LOCKED": FailureClass.TRANSIENT,
        "WAL_RETRY_EXHAUSTED": FailureClass.TRANSIENT,
        "VALIDATION_FAIL": FailureClass.DETERMINISTIC,
        "DIFF_EMPTY": FailureClass.DETERMINISTIC,
        "DIFF_MALFORMED": FailureClass.DETERMINISTIC,
        "SHA_MALFORMED": FailureClass.DETERMINISTIC,
        "DIFF_SIZE_MISMATCH": FailureClass.DETERMINISTIC,
        "FUNCTIONAL_TESTS_FAILED": FailureClass.BUSINESS,
        "CYCLOMATIC_DELTA_EXCEEDED": FailureClass.BUSINESS,
        "DISALLOWED_IMPORT": FailureClass.BUSINESS,
        "TYPE_IGNORE_INTRODUCED": FailureClass.BUSINESS,
        "LEDGER_MUTATION_ATTEMPT": FailureClass.SECURITY,
        "VERDICT_FORGERY_ATTEMPT": FailureClass.SECURITY,
    }
)

# Disposition per class. Every disposition denies the merge (fail-closed).
FAILURE_DISPOSITION: Mapping[FailureClass, str] = MappingProxyType(
    {
        FailureClass.TRANSIENT: "RETRY_BOUNDED_3_THEN_QUARANTINE",
        FailureClass.DETERMINISTIC: "REJECT_AND_QUARANTINE",
        FailureClass.BUSINESS: "DENY_MERGE",
        FailureClass.SECURITY: "ABORT_AND_QUARANTINE",
    }
)


def transition(state: object, event: object) -> GateState:
    """Total FSM function delta(S, E). Never raises; unknown input -> REJECTED_INVALID."""
    if not isinstance(state, GateState) or not isinstance(event, GateEvent):
        return GateState.REJECTED_INVALID
    if state in TERMINAL_STATES:
        return state
    return TRANSITION_TABLE.get((state, event), GateState.REJECTED_INVALID)


def classify_failure(code: object) -> FailureClass:
    """Route a failure code to its class. Never raises; an unknown code is DETERMINISTIC."""
    if not isinstance(code, str):
        return FailureClass.DETERMINISTIC
    return FAILURE_ROUTING.get(code, FailureClass.DETERMINISTIC)


# ----------------------------------------------------------------------------
# Deterministic helpers (no clock, no randomness, no floats)
# ----------------------------------------------------------------------------
def sha256_hex(text: str) -> str:
    """Lowercase-hex SHA-256 of the UTF-8 encoding of text."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def derive_gate_id(prefix: str, *parts: object) -> str:
    """Deterministic id: prefix + first 16 hex chars of sha256 over the joined parts."""
    if prefix not in _ID_PREFIXES:
        raise ValueError("prefix must be one of REPO-, EVL-, VIO-, RULE-")
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return prefix + digest[:16]


def format_violation(violation_type: ViolationType, location: str) -> str:
    """Build the canonical entry TYPE|LOCATION. Rejects unknown types and bad locations."""
    if not isinstance(violation_type, ViolationType):
        raise ValueError("violation_type must be a ViolationType")
    if not isinstance(location, str):
        raise ValueError("location must be str")
    entry = violation_type.value + "|" + location
    if len(entry) > VIOLATION_ENTRY_MAX or _VIOLATION_RE.fullmatch(entry) is None:
        raise ValueError("location violates the violation entry pattern")
    return entry


def split_violation(entry: str) -> Tuple[ViolationType, str]:
    """Inverse of format_violation. Raises ValueError for any malformed entry."""
    if not isinstance(entry, str):
        raise ValueError("violation entry must be str")
    if len(entry) > VIOLATION_ENTRY_MAX or _VIOLATION_RE.fullmatch(entry) is None:
        raise ValueError("violation entry violates TYPE|LOCATION pattern")
    head, _, location = entry.partition("|")
    try:
        return ViolationType(head), location
    except ValueError:
        raise ValueError("violation type is outside the closed set") from None


def decide_gate_verdict(is_functional_passed: bool, violations: Tuple[str, ...]) -> GateVerdict:
    """ALLOW_MERGE iff the functional tests passed and no violation was recorded."""
    if is_functional_passed is True and len(violations) == 0:
        return GateVerdict.ALLOW_MERGE
    return GateVerdict.REJECT_ARCHITECTURAL_VIOLATION


def _require_module_name(value: str) -> str:
    if _MODULE_RE.fullmatch(value) is None:
        raise ValueError("module name must be a dotted identifier")
    return value


def _require_violation_entry(value: str) -> str:
    split_violation(value)
    return value


CommitSha = Annotated[str, Field(pattern=COMMIT_SHA_PATTERN, strict=True)]
PrId = Annotated[int, Field(strict=True, ge=PR_ID_MIN, le=PR_ID_MAX)]
DiffSizeBytes = Annotated[int, Field(strict=True, ge=DIFF_SIZE_MIN, le=DIFF_SIZE_MAX)]
TestsCount = Annotated[int, Field(strict=True, ge=TESTS_COUNT_MIN, le=TESTS_COUNT_MAX)]
MaxCyclomaticDelta = Annotated[
    int, Field(strict=True, ge=MAX_CYCLOMATIC_DELTA_MIN, le=MAX_CYCLOMATIC_DELTA_MAX)
]
CyclomaticDelta = Annotated[
    int, Field(strict=True, ge=CYCLOMATIC_DELTA_MIN, le=CYCLOMATIC_DELTA_MAX)
]
ModuleName = Annotated[
    str, Field(strict=True, min_length=1, max_length=MODULE_NAME_MAX), AfterValidator(_require_module_name)
]
ViolationEntry = Annotated[
    str, Field(strict=True, min_length=5, max_length=VIOLATION_ENTRY_MAX), AfterValidator(_require_violation_entry)
]


# ----------------------------------------------------------------------------
# Immutable DTOs
# ----------------------------------------------------------------------------
class SweGateBaseDTO(BaseModel):
    """Common immutable configuration for every SWE-Gate contract."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


class PatchMetadataDTO(SweGateBaseDTO):
    """Identity of the patch under review; diff_size_bytes is the real UTF-8 size of the diff."""

    commit_sha: CommitSha
    author_kind: AuthorKind
    pr_id: PrId
    diff_size_bytes: DiffSizeBytes


class FunctionalTestResultDTO(SweGateBaseDTO):
    """Pytest report summary. PASSED requires tests_failed == 0 and tests_passed >= 1."""

    tests_passed: TestsCount
    tests_failed: TestsCount
    functional_verdict: FunctionalVerdict

    @model_validator(mode="after")
    def _verdict_matches_counters(self) -> "FunctionalTestResultDTO":
        expected = (
            FunctionalVerdict.PASSED
            if self.tests_failed == 0 and self.tests_passed >= 1
            else FunctionalVerdict.FAILED
        )
        if self.functional_verdict is not expected:
            raise ValueError("functional_verdict contradicts tests_passed / tests_failed")
        return self


class ArchitecturalConstraintRuleDTO(SweGateBaseDTO):
    """Review constraints the patch must honour besides the functional tests."""

    rule_id: str = Field(pattern=RULE_ID_PATTERN, strict=True)
    max_cyclomatic_delta: MaxCyclomaticDelta
    forbid_type_ignores: bool = Field(strict=True)
    disallowed_import_modules: Annotated[
        Tuple[ModuleName, ...], Field(strict=True, max_length=DISALLOWED_MODULES_MAX)
    ]

    @model_validator(mode="after")
    def _modules_are_unique(self) -> "ArchitecturalConstraintRuleDTO":
        if len(set(self.disallowed_import_modules)) != len(self.disallowed_import_modules):
            raise ValueError("disallowed_import_modules must not contain duplicates")
        return self


class PatchInspectionAuditDTO(SweGateBaseDTO):
    """Outcome of the static inspection; gate_verdict must equal decide_gate_verdict(...)."""

    is_functional_passed: bool = Field(strict=True)
    cyclomatic_delta: CyclomaticDelta
    architectural_violations: Annotated[
        Tuple[ViolationEntry, ...], Field(strict=True, max_length=VIOLATIONS_MAX)
    ]
    gate_verdict: GateVerdict

    @model_validator(mode="after")
    def _verdict_is_consistent(self) -> "PatchInspectionAuditDTO":
        expected = decide_gate_verdict(self.is_functional_passed, self.architectural_violations)
        if self.gate_verdict is not expected:
            raise ValueError(
                "gate_verdict must be ALLOW_MERGE if and only if the functional tests passed "
                "and there are no architectural violations"
            )
        return self
