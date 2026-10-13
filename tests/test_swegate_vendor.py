# manifest_hash: f65c9e8fcc9152df8275d94641f7e9d4c8bd8e88072359102e32b1e849187710
"""Gate G9 for ctxfw.swegate: vendored SWE-Gate CI Verifier blueprint files must stay byte-for-byte sealed.

Validates:
1. Sealed blueprint manifest metadata and Merkle/ACI attestation.
2. Exact SHA-256 match for contracts.py and schema.sql against blueprint_manifest.json.
3. Presence of sealed blueprint and M4-P1 manifest_hash headers across files.
4. Complete absence of carriage return (\\r) bytes across all vendored and package files (zero CRLF).
5. Clean and lazy import of ctxfw.swegate (zero heavy dependencies loaded at import time).
6. Pydantic v2 DTO instantiation, immutability (frozen=True, extra="forbid"),
   domain bounds, and deterministic helper functions.
7. Deterministic total FSM transition(S, E) across 9 states x 8 events = 72 pairs,
   absorbing terminal states, fail-closed collapse, and failure taxonomy routing.
8. Schema loading, 3 tables, 4 indexes, 6 triggers of immutability and count caps,
   verdict consistency CHECK constraints, and cascade deletion from swe_gate_repositories.
9. Multi-threaded contention under SQLite WAL mode (10 concurrent worker threads).
"""
from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from ctxfw.swegate import (
    CONTRACTS_PATH,
    MANIFEST_PATH,
    PACKAGE_DIR,
    SCHEMA_PATH,
    load_manifest,
    load_schema_sql,
)

M4_P1_MANIFEST_HASH = "f65c9e8fcc9152df8275d94641f7e9d4c8bd8e88072359102e32b1e849187710"
BLUEPRINT_MANIFEST_HASH = "8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f"
EXPECTED_CONTRACTS_SHA256 = "6e39ade14eea86d5882e3bd78049af257a11b981b9d5d5faeb3bf44094e6adb0"
EXPECTED_SCHEMA_SHA256 = "bee1f2b3cb640939c25e37c0a52cd52ff5576c16cccf64d20a67d810caa908f4"
THIS_TEST_FILE = Path(__file__).resolve()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_manifest_is_the_sealed_swegate_manifest():
    manifest = load_manifest()
    assert manifest["blueprint_id"] == "BP-SIG-673052a2a791ec2b-SWE-GATE-CI-VERIFIER"
    assert manifest["signal_id"] == "SIG-673052a2a791ec2b"
    assert manifest["proposal_id"] == "PROP-673052a2a791ec2b-H1"
    assert manifest["horizon"] == "HORIZON_1"
    assert manifest["architecture_standard"] == "HEURISTICO_LAB_SOVEREIGN_BLUEPRINT_V2"
    assert manifest["merkle_root_sha256"] == "11a0c985e0ac5da98553feead48621640f5fb47d78e71e890f54a4ea6453e98a"
    assert manifest["ctxfw"]["status"] == "VERIFIED"
    assert manifest["ctxfw"]["aci_score"] == 1.0
    assert manifest["ctxfw"]["manifest_hash"] == BLUEPRINT_MANIFEST_HASH
    assert manifest["hermetic_compiler"]["ast_valid"] is True
    assert manifest["hermetic_compiler"]["ddl_valid"] is True
    assert manifest["hermetic_compiler"]["semantic_gate_enforced"] is True
    assert manifest["hermetic_compiler"]["passed_tests"] == 62
    assert manifest["hermetic_compiler"]["warnings"] == 0


def test_vendored_contracts_and_schema_match_sealed_sha256():
    deliverables = load_manifest()["deliverables"]
    assert deliverables["specs/2_pydantic_contracts.py"]["sha256"] == EXPECTED_CONTRACTS_SHA256
    assert deliverables["specs/3_schema_ddl.sql"]["sha256"] == EXPECTED_SCHEMA_SHA256
    assert _sha256(CONTRACTS_PATH) == EXPECTED_CONTRACTS_SHA256
    assert _sha256(SCHEMA_PATH) == EXPECTED_SCHEMA_SHA256


def test_vendored_files_carry_the_blueprint_hash_header():
    assert BLUEPRINT_MANIFEST_HASH in CONTRACTS_PATH.read_text(encoding="utf-8")
    assert BLUEPRINT_MANIFEST_HASH in load_schema_sql()
    init_text = (PACKAGE_DIR / "__init__.py").read_text(encoding="utf-8")
    test_text = THIS_TEST_FILE.read_text(encoding="utf-8")
    assert init_text.startswith(f"# manifest_hash: {M4_P1_MANIFEST_HASH}\n")
    assert test_text.startswith(f"# manifest_hash: {M4_P1_MANIFEST_HASH}\n")


def test_vendored_files_have_no_crlf():
    for path in (
        CONTRACTS_PATH,
        SCHEMA_PATH,
        MANIFEST_PATH,
        PACKAGE_DIR / "__init__.py",
        THIS_TEST_FILE,
    ):
        assert b"\r" not in path.read_bytes(), f"{path.name} was rewritten with CR (line-ending drift)"


def test_swegate_package_import_is_lazy():
    code = (
        "import sys, ctxfw.swegate;"
        "assert 'ctxfw.swegate.contracts' not in sys.modules;"
        "print([m for m in sys.modules if m=='ctxfw.swegate.contracts'])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"

    code_access = (
        "import sys, ctxfw.swegate;"
        "mod = ctxfw.swegate.contracts;"
        "assert 'ctxfw.swegate.contracts' in sys.modules;"
        "dto_cls = ctxfw.swegate.PatchMetadataDTO;"
        "assert dto_cls is mod.PatchMetadataDTO;"
        "assert 'PatchMetadataDTO' in dir(ctxfw.swegate);"
        "assert 'contracts' in dir(ctxfw.swegate);"
        "print('ACCESS_OK')"
    )
    out_access = subprocess.run([sys.executable, "-c", code_access], capture_output=True, text=True, check=True)
    assert out_access.stdout.strip() == "ACCESS_OK"

    import ctxfw.swegate as swegate_pkg

    for sym in swegate_pkg.__all__:
        assert hasattr(swegate_pkg, sym), f"Missing exported symbol in ctxfw.swegate: {sym}"

    with pytest.raises(AttributeError, match="has no attribute 'NON_EXISTENT_SYMBOL'"):
        _ = swegate_pkg.NON_EXISTENT_SYMBOL


def test_pydantic_v2_dtos_instantiation_and_invariants():
    from ctxfw.swegate import (
        COMMIT_SHA_LEN,
        CYCLOMATIC_DELTA_MAX,
        CYCLOMATIC_DELTA_MIN,
        DIFF_LINES_MAX,
        DIFF_SIZE_MAX,
        DIFF_SIZE_MIN,
        DISALLOWED_MODULES_MAX,
        INSPECTION_LATENCY_BUDGET_MS,
        MAX_CYCLOMATIC_DELTA_MAX,
        MAX_CYCLOMATIC_DELTA_MIN,
        MODULE_NAME_MAX,
        PR_ID_MAX,
        PR_ID_MIN,
        TESTS_COUNT_MAX,
        TESTS_COUNT_MIN,
        VIOLATION_ENTRY_MAX,
        VIOLATION_LOCATION_MAX,
        VIOLATIONS_MAX,
        WAL_RETRY_ATTEMPTS_MAX,
        ArchitecturalConstraintRuleDTO,
        AuthorKind,
        FunctionalTestResultDTO,
        FunctionalVerdict,
        GateVerdict,
        PatchInspectionAuditDTO,
        PatchMetadataDTO,
        SweGateBaseDTO,
        ViolationType,
        decide_gate_verdict,
        derive_gate_id,
        format_violation,
        sha256_hex,
        split_violation,
    )

    assert COMMIT_SHA_LEN == 40
    assert (PR_ID_MIN, PR_ID_MAX) == (1, 2_147_483_647)
    assert (DIFF_SIZE_MIN, DIFF_SIZE_MAX, DIFF_LINES_MAX) == (1, 1_048_576, 20_000)
    assert (TESTS_COUNT_MIN, TESTS_COUNT_MAX) == (0, 1_000_000)
    assert (MAX_CYCLOMATIC_DELTA_MIN, MAX_CYCLOMATIC_DELTA_MAX) == (0, 10_000)
    assert (CYCLOMATIC_DELTA_MIN, CYCLOMATIC_DELTA_MAX) == (-1_000_000, 1_000_000)
    assert (DISALLOWED_MODULES_MAX, MODULE_NAME_MAX) == (64, 128)
    assert (VIOLATIONS_MAX, VIOLATION_ENTRY_MAX, VIOLATION_LOCATION_MAX) == (256, 500, 480)
    assert WAL_RETRY_ATTEMPTS_MAX == 3
    assert INSPECTION_LATENCY_BUDGET_MS == 5.0

    # 1. PatchMetadataDTO valid & boundaries
    valid_sha = "a" * 40
    patch = PatchMetadataDTO(
        commit_sha=valid_sha,
        author_kind=AuthorKind.AGENT,
        pr_id=1,
        diff_size_bytes=1,
    )
    assert isinstance(patch, SweGateBaseDTO)
    assert patch.commit_sha == valid_sha
    assert patch.author_kind is AuthorKind.AGENT
    assert patch.pr_id == 1
    assert patch.diff_size_bytes == 1

    patch_max = PatchMetadataDTO(
        commit_sha="0123456789abcdef0123456789abcdef01234567",
        author_kind=AuthorKind.HUMAN,
        pr_id=PR_ID_MAX,
        diff_size_bytes=DIFF_SIZE_MAX,
    )
    assert patch_max.pr_id == PR_ID_MAX
    assert patch_max.diff_size_bytes == DIFF_SIZE_MAX

    # frozen=True & extra="forbid"
    with pytest.raises(ValidationError):
        patch.pr_id = 2  # type: ignore[misc]
    with pytest.raises(ValidationError):
        PatchMetadataDTO(
            commit_sha=valid_sha,
            author_kind=AuthorKind.AGENT,
            pr_id=1,
            diff_size_bytes=10,
            extra_field="denied",  # type: ignore[call-arg]
        )

    # commit_sha bounds (must be 40 lowercase hex chars)
    for bad_sha in ("a" * 39, "a" * 41, "A" * 40, "g" * 40, ""):
        with pytest.raises(ValidationError):
            PatchMetadataDTO(
                commit_sha=bad_sha,
                author_kind=AuthorKind.AGENT,
                pr_id=1,
                diff_size_bytes=10,
            )

    # pr_id & diff_size_bytes bounds
    for bad_pr in (0, -1, PR_ID_MAX + 1):
        with pytest.raises(ValidationError):
            PatchMetadataDTO(
                commit_sha=valid_sha,
                author_kind=AuthorKind.AGENT,
                pr_id=bad_pr,
                diff_size_bytes=10,
            )
    for bad_diff_size in (0, -5, DIFF_SIZE_MAX + 1):
        with pytest.raises(ValidationError):
            PatchMetadataDTO(
                commit_sha=valid_sha,
                author_kind=AuthorKind.AGENT,
                pr_id=1,
                diff_size_bytes=bad_diff_size,
            )

    # 2. FunctionalTestResultDTO valid & counter consistency
    res_pass = FunctionalTestResultDTO(
        tests_passed=1,
        tests_failed=0,
        functional_verdict=FunctionalVerdict.PASSED,
    )
    assert res_pass.functional_verdict is FunctionalVerdict.PASSED

    res_fail_nonzero = FunctionalTestResultDTO(
        tests_passed=10,
        tests_failed=1,
        functional_verdict=FunctionalVerdict.FAILED,
    )
    assert res_fail_nonzero.functional_verdict is FunctionalVerdict.FAILED

    res_fail_zero_total = FunctionalTestResultDTO(
        tests_passed=0,
        tests_failed=0,
        functional_verdict=FunctionalVerdict.FAILED,
    )
    assert res_fail_zero_total.functional_verdict is FunctionalVerdict.FAILED

    # Contradictory functional_verdict rejected
    with pytest.raises(ValidationError, match="functional_verdict contradicts"):
        FunctionalTestResultDTO(
            tests_passed=0,
            tests_failed=0,
            functional_verdict=FunctionalVerdict.PASSED,
        )
    with pytest.raises(ValidationError, match="functional_verdict contradicts"):
        FunctionalTestResultDTO(
            tests_passed=5,
            tests_failed=1,
            functional_verdict=FunctionalVerdict.PASSED,
        )
    with pytest.raises(ValidationError, match="functional_verdict contradicts"):
        FunctionalTestResultDTO(
            tests_passed=5,
            tests_failed=0,
            functional_verdict=FunctionalVerdict.FAILED,
        )
    for bad_cnt in (-1, TESTS_COUNT_MAX + 1):
        with pytest.raises(ValidationError):
            FunctionalTestResultDTO(
                tests_passed=bad_cnt,
                tests_failed=0,
                functional_verdict=FunctionalVerdict.PASSED,
            )

    # 3. ArchitecturalConstraintRuleDTO valid, uniqueness & bounds
    rule = ArchitecturalConstraintRuleDTO(
        rule_id="RULE-arch0001",
        max_cyclomatic_delta=5,
        forbid_type_ignores=True,
        disallowed_import_modules=("os.path", "subprocess", "_private.mod_1"),
    )
    assert rule.rule_id == "RULE-arch0001"
    assert len(rule.disallowed_import_modules) == 3

    # Duplicate disallowed_import_modules rejected
    with pytest.raises(ValidationError, match="disallowed_import_modules must not contain duplicates"):
        ArchitecturalConstraintRuleDTO(
            rule_id="RULE-arch0002",
            max_cyclomatic_delta=5,
            forbid_type_ignores=True,
            disallowed_import_modules=("subprocess", "subprocess"),
        )

    # Invalid module names rejected
    for bad_mod in ("", "123bad", "bad..mod", ".leading", "trailing.", "bad-dash", "a" * (MODULE_NAME_MAX + 1)):
        with pytest.raises(ValidationError):
            ArchitecturalConstraintRuleDTO(
                rule_id="RULE-arch0003",
                max_cyclomatic_delta=5,
                forbid_type_ignores=True,
                disallowed_import_modules=(bad_mod,),
            )

    # Oversized disallowed_import_modules tuple (>64) rejected
    with pytest.raises(ValidationError):
        ArchitecturalConstraintRuleDTO(
            rule_id="RULE-arch0004",
            max_cyclomatic_delta=5,
            forbid_type_ignores=True,
            disallowed_import_modules=tuple(f"mod_{i}" for i in range(DISALLOWED_MODULES_MAX + 1)),
        )

    # max_cyclomatic_delta and rule_id bounds
    for bad_max_cyc in (-1, MAX_CYCLOMATIC_DELTA_MAX + 1):
        with pytest.raises(ValidationError):
            ArchitecturalConstraintRuleDTO(
                rule_id="RULE-arch0005",
                max_cyclomatic_delta=bad_max_cyc,
                forbid_type_ignores=False,
                disallowed_import_modules=(),
            )
    with pytest.raises(ValidationError):
        ArchitecturalConstraintRuleDTO(
            rule_id="BAD-ID",
            max_cyclomatic_delta=0,
            forbid_type_ignores=False,
            disallowed_import_modules=(),
        )

    # 4. Helpers: sha256_hex, derive_gate_id, format_violation, split_violation, decide_gate_verdict
    assert sha256_hex("swe-gate") == hashlib.sha256(b"swe-gate").hexdigest()
    with pytest.raises(TypeError, match="text must be str"):
        sha256_hex(12345)  # type: ignore[arg-type]

    for prefix in ("REPO-", "EVL-", "VIO-", "RULE-"):
        gid = derive_gate_id(prefix, "part1", 42)
        assert gid.startswith(prefix)
        assert len(gid) == len(prefix) + 16
        assert gid == derive_gate_id(prefix, "part1", 42)
    with pytest.raises(ValueError, match="prefix must be one of"):
        derive_gate_id("BAD-", "part1")

    entry_ti = format_violation(ViolationType.TYPE_IGNORE, "src/app.py:42")
    assert entry_ti == "TYPE_IGNORE|src/app.py:42"
    v_type, v_loc = split_violation(entry_ti)
    assert v_type is ViolationType.TYPE_IGNORE
    assert v_loc == "src/app.py:42"

    with pytest.raises(ValueError, match="violation_type must be a ViolationType"):
        format_violation("TYPE_IGNORE", "src/app.py:1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="location must be str"):
        format_violation(ViolationType.TYPE_IGNORE, 123)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="location violates"):
        format_violation(ViolationType.TYPE_IGNORE, "")
    with pytest.raises(ValueError, match="location violates"):
        format_violation(ViolationType.TYPE_IGNORE, "bad\x00loc")
    with pytest.raises(ValueError, match="location violates"):
        format_violation(ViolationType.TYPE_IGNORE, "a" * (VIOLATION_LOCATION_MAX + 1))

    with pytest.raises(ValueError, match="violation entry must be str"):
        split_violation(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="violates TYPE\\|LOCATION pattern"):
        split_violation("no_pipe_separator")
    with pytest.raises(ValueError, match="outside the closed set"):
        split_violation("UNKNOWN_TYPE|src/app.py:10")

    assert decide_gate_verdict(True, ()) is GateVerdict.ALLOW_MERGE
    assert decide_gate_verdict(False, ()) is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert decide_gate_verdict(True, (entry_ti,)) is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert decide_gate_verdict(False, (entry_ti,)) is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION

    # 5. PatchInspectionAuditDTO valid & verdict consistency
    audit_allow = PatchInspectionAuditDTO(
        is_functional_passed=True,
        cyclomatic_delta=0,
        architectural_violations=(),
        gate_verdict=GateVerdict.ALLOW_MERGE,
    )
    assert audit_allow.gate_verdict is GateVerdict.ALLOW_MERGE

    audit_reject_viol = PatchInspectionAuditDTO(
        is_functional_passed=True,
        cyclomatic_delta=8,
        architectural_violations=(entry_ti,),
        gate_verdict=GateVerdict.REJECT_ARCHITECTURAL_VIOLATION,
    )
    assert audit_reject_viol.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION

    audit_reject_func = PatchInspectionAuditDTO(
        is_functional_passed=False,
        cyclomatic_delta=-3,
        architectural_violations=(),
        gate_verdict=GateVerdict.REJECT_ARCHITECTURAL_VIOLATION,
    )
    assert audit_reject_func.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION

    # Inconsistent gate_verdict rejected (INV-04)
    with pytest.raises(ValidationError, match="gate_verdict must be ALLOW_MERGE if and only if"):
        PatchInspectionAuditDTO(
            is_functional_passed=False,
            cyclomatic_delta=0,
            architectural_violations=(),
            gate_verdict=GateVerdict.ALLOW_MERGE,
        )
    with pytest.raises(ValidationError, match="gate_verdict must be ALLOW_MERGE if and only if"):
        PatchInspectionAuditDTO(
            is_functional_passed=True,
            cyclomatic_delta=0,
            architectural_violations=(entry_ti,),
            gate_verdict=GateVerdict.ALLOW_MERGE,
        )
    with pytest.raises(ValidationError, match="gate_verdict must be ALLOW_MERGE if and only if"):
        PatchInspectionAuditDTO(
            is_functional_passed=True,
            cyclomatic_delta=0,
            architectural_violations=(),
            gate_verdict=GateVerdict.REJECT_ARCHITECTURAL_VIOLATION,
        )

    # Oversized architectural_violations (>256) rejected
    with pytest.raises(ValidationError):
        PatchInspectionAuditDTO(
            is_functional_passed=True,
            cyclomatic_delta=0,
            architectural_violations=tuple(
                format_violation(ViolationType.TYPE_IGNORE, f"src/f_{i}.py:1")
                for i in range(VIOLATIONS_MAX + 1)
            ),
            gate_verdict=GateVerdict.REJECT_ARCHITECTURAL_VIOLATION,
        )


def test_swegate_fsm_total_and_fail_closed():
    from ctxfw.swegate import (
        FAILURE_DISPOSITION,
        FAILURE_ROUTING,
        GATE_VERDICT_TO_TERMINAL,
        TERMINAL_STATES,
        TRANSITION_TABLE,
        FailureClass,
        GateEvent,
        GateState,
        GateVerdict,
        classify_failure,
        transition,
    )

    assert len(GateState) == 9
    assert len(GateEvent) == 8
    assert len(TRANSITION_TABLE) == 13
    assert TERMINAL_STATES == frozenset(
        {
            GateState.PASS_GATE,
            GateState.REJECT_NON_FUNCTIONAL_REGRESSION,
            GateState.REJECTED_INVALID,
        }
    )

    # Verify all 13 explicit transitions
    assert transition(GateState.RECEIVED, GateEvent.PATCH_OK) is GateState.PATCH_INGESTED
    assert transition(GateState.RECEIVED, GateEvent.VALIDATION_FAIL) is GateState.REJECTED_INVALID
    assert transition(GateState.PATCH_INGESTED, GateEvent.REPORT_OK) is GateState.REPORT_INGESTED
    assert transition(GateState.PATCH_INGESTED, GateEvent.VALIDATION_FAIL) is GateState.REJECTED_INVALID
    assert transition(GateState.REPORT_INGESTED, GateEvent.INSPECT_OK) is GateState.INSPECTED
    assert transition(GateState.REPORT_INGESTED, GateEvent.VALIDATION_FAIL) is GateState.REJECTED_INVALID
    assert transition(GateState.INSPECTED, GateEvent.CONSTRAINTS_MET) is GateState.DECIDED_PASS
    assert transition(GateState.INSPECTED, GateEvent.CONSTRAINTS_VIOLATED) is GateState.DECIDED_REJECT
    assert transition(GateState.INSPECTED, GateEvent.VALIDATION_FAIL) is GateState.REJECTED_INVALID
    assert transition(GateState.DECIDED_PASS, GateEvent.WAL_COMMIT) is GateState.PASS_GATE
    assert transition(GateState.DECIDED_PASS, GateEvent.WAL_RETRY_EXHAUSTED) is GateState.REJECTED_INVALID
    assert (
        transition(GateState.DECIDED_REJECT, GateEvent.WAL_COMMIT)
        is GateState.REJECT_NON_FUNCTIONAL_REGRESSION
    )
    assert transition(GateState.DECIDED_REJECT, GateEvent.WAL_RETRY_EXHAUSTED) is GateState.REJECTED_INVALID

    # Total determinism over 9 states x 8 events = 72 pairs
    pair_count = 0
    for state in GateState:
        for event in GateEvent:
            pair_count += 1
            nxt = transition(state, event)
            assert isinstance(nxt, GateState)
            assert nxt is transition(state, event)
            if state in TERMINAL_STATES:
                # Terminal states are absorbing
                assert nxt is state
            elif (state, event) in TRANSITION_TABLE:
                assert nxt is TRANSITION_TABLE[(state, event)]
            else:
                assert nxt is GateState.REJECTED_INVALID
    assert pair_count == 72

    # Invalid types collapse to REJECTED_INVALID without raising
    assert transition("RECEIVED", GateEvent.PATCH_OK) is GateState.REJECTED_INVALID
    assert transition(GateState.RECEIVED, "PATCH_OK") is GateState.REJECTED_INVALID
    assert transition(None, None) is GateState.REJECTED_INVALID

    # Immutability of mapping tables
    for mapping in (TRANSITION_TABLE, GATE_VERDICT_TO_TERMINAL, FAILURE_ROUTING, FAILURE_DISPOSITION):
        with pytest.raises(TypeError):
            mapping["mutated"] = "forbidden"  # type: ignore[index]

    assert GATE_VERDICT_TO_TERMINAL[GateVerdict.ALLOW_MERGE] is GateState.PASS_GATE
    assert (
        GATE_VERDICT_TO_TERMINAL[GateVerdict.REJECT_ARCHITECTURAL_VIOLATION]
        is GateState.REJECT_NON_FUNCTIONAL_REGRESSION
    )

    # Failure taxonomy routing & disposition
    assert len(FAILURE_ROUTING) == 13
    assert len(FAILURE_DISPOSITION) == 4
    for code, expected_class in FAILURE_ROUTING.items():
        assert classify_failure(code) is expected_class
        assert expected_class in FAILURE_DISPOSITION
    assert classify_failure("UNKNOWN_FAILURE_CODE") is FailureClass.DETERMINISTIC
    assert classify_failure(404) is FailureClass.DETERMINISTIC


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 37, 0), reason="sealed DDL requires SQLite >= 3.37")
def test_sealed_schema_loads_and_has_immutability_triggers():
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(load_schema_sql())

        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {
            "swe_gate_repositories",
            "swe_gate_patch_evaluations",
            "swe_gate_violation_findings",
        } <= tables

        indexes = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_swe_gate_%'"
            )
        }
        assert indexes == {
            "idx_swe_gate_evaluations_repo_time",
            "idx_swe_gate_evaluations_commit",
            "idx_swe_gate_evaluations_verdict_time",
            "idx_swe_gate_violations_evaluation",
        }

        triggers = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert triggers == {
            "trg_swe_gate_repositories_no_update",
            "trg_swe_gate_evaluations_no_update",
            "trg_swe_gate_violations_no_update",
            "trg_swe_gate_evaluations_no_direct_delete",
            "trg_swe_gate_violations_no_direct_delete",
            "trg_swe_gate_violations_count_cap",
        }

        # 1. Insert repository and verify no-UPDATE trigger
        conn.execute(
            "INSERT INTO swe_gate_repositories (repo_id, repo_name) VALUES ('REPO-core0001', 'heuristico/ctxfw')"
        )
        with pytest.raises(sqlite3.IntegrityError, match="swe_gate_repositories is immutable: UPDATE forbidden"):
            conn.execute(
                "UPDATE swe_gate_repositories SET repo_name = 'tampered' WHERE repo_id = 'REPO-core0001'"
            )

        # 2. Verdict consistency CHECK constraints on swe_gate_patch_evaluations
        sha = "b" * 40
        # ALLOW_MERGE with functional_passed = 0 -> rejected
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO swe_gate_patch_evaluations "
                "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
                "VALUES ('EVL-badallow1', 'REPO-core0001', ?, 0, 'ALLOW_MERGE', 0)",
                (sha,),
            )
        # ALLOW_MERGE with violations_count > 0 -> rejected
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO swe_gate_patch_evaluations "
                "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
                "VALUES ('EVL-badallow2', 'REPO-core0001', ?, 1, 'ALLOW_MERGE', 1)",
                (sha,),
            )
        # REJECT_ARCHITECTURAL_VIOLATION with functional_passed = 1 and violations_count = 0 -> rejected
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO swe_gate_patch_evaluations "
                "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
                "VALUES ('EVL-badreject', 'REPO-core0001', ?, 1, 'REJECT_ARCHITECTURAL_VIOLATION', 0)",
                (sha,),
            )

        # Valid ALLOW_MERGE evaluation (violations_count = 0)
        conn.execute(
            "INSERT INTO swe_gate_patch_evaluations "
            "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
            "VALUES ('EVL-allow0001', 'REPO-core0001', ?, 1, 'ALLOW_MERGE', 0)",
            (sha,),
        )
        # Cap trigger blocks inserting any violation into an evaluation with violations_count = 0
        with pytest.raises(
            sqlite3.IntegrityError, match="violation records exceed violations_count of the evaluation"
        ):
            conn.execute(
                "INSERT INTO swe_gate_violation_findings "
                "(violation_id, evaluation_id, violation_type, symbol_or_file) "
                "VALUES ('VIO-cap00001', 'EVL-allow0001', 'TYPE_IGNORE', 'src/main.py:10')"
            )

        # Valid REJECT_ARCHITECTURAL_VIOLATION evaluation with violations_count = 1
        conn.execute(
            "INSERT INTO swe_gate_patch_evaluations "
            "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
            "VALUES ('EVL-rej00001', 'REPO-core0001', ?, 1, 'REJECT_ARCHITECTURAL_VIOLATION', 1)",
            (sha,),
        )
        with pytest.raises(
            sqlite3.IntegrityError, match="swe_gate_patch_evaluations is immutable: UPDATE forbidden"
        ):
            conn.execute(
                "UPDATE swe_gate_patch_evaluations SET gate_verdict = 'ALLOW_MERGE', violations_count = 0 "
                "WHERE evaluation_id = 'EVL-rej00001'"
            )

        # Insert 1 violation (allowed by cap = 1)
        conn.execute(
            "INSERT INTO swe_gate_violation_findings "
            "(violation_id, evaluation_id, violation_type, symbol_or_file) "
            "VALUES ('VIO-viol0001', 'EVL-rej00001', 'DISALLOWED_IMPORT', 'src/agent.py:7')"
        )
        # 2nd violation exceeds violations_count = 1 -> aborted by trg_swe_gate_violations_count_cap
        with pytest.raises(
            sqlite3.IntegrityError, match="violation records exceed violations_count of the evaluation"
        ):
            conn.execute(
                "INSERT INTO swe_gate_violation_findings "
                "(violation_id, evaluation_id, violation_type, symbol_or_file) "
                "VALUES ('VIO-viol0002', 'EVL-rej00001', 'TYPE_IGNORE', 'src/agent.py:12')"
            )

        # Violation no-UPDATE trigger
        with pytest.raises(
            sqlite3.IntegrityError, match="swe_gate_violation_findings is immutable: UPDATE forbidden"
        ):
            conn.execute(
                "UPDATE swe_gate_violation_findings SET symbol_or_file = 'other.py:1' "
                "WHERE violation_id = 'VIO-viol0001'"
            )

        # Direct DELETE on child tables is forbidden while parent exists
        with pytest.raises(
            sqlite3.IntegrityError,
            match="swe_gate_violation_findings is append-only: direct DELETE forbidden",
        ):
            conn.execute("DELETE FROM swe_gate_violation_findings WHERE violation_id = 'VIO-viol0001'")

        with pytest.raises(
            sqlite3.IntegrityError,
            match="swe_gate_patch_evaluations is append-only: direct DELETE forbidden",
        ):
            conn.execute("DELETE FROM swe_gate_patch_evaluations WHERE evaluation_id = 'EVL-rej00001'")

        # Cascade DELETE from swe_gate_repositories removes evaluations and violations cleanly
        conn.execute("DELETE FROM swe_gate_repositories WHERE repo_id = 'REPO-core0001'")
        eval_rem = conn.execute("SELECT COUNT(*) FROM swe_gate_patch_evaluations").fetchone()[0]
        viol_rem = conn.execute("SELECT COUNT(*) FROM swe_gate_violation_findings").fetchone()[0]
        assert eval_rem == 0
        assert viol_rem == 0
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def test_sqlite_wal_multithread_contention(tmp_path):
    """10 worker threads concurrently inserting repositories, evaluations, and violations under SQLite WAL mode."""
    db_file = tmp_path / "swegate_wal_contention.db"

    init_conn = sqlite3.connect(db_file)
    init_conn.execute("PRAGMA journal_mode=WAL")
    init_conn.execute("PRAGMA foreign_keys=ON")
    init_conn.executescript(load_schema_sql())
    init_conn.commit()
    init_conn.close()

    worker_errors: list[Exception] = []

    def thread_worker(worker_id: int) -> None:
        try:
            w_conn = sqlite3.connect(db_file, timeout=10.0)
            w_conn.execute("PRAGMA busy_timeout=10000")
            w_conn.execute("PRAGMA foreign_keys=ON")
            repo_id = f"REPO-worker-{worker_id:04d}"
            eval_id = f"EVL-worker-{worker_id:04d}"
            sha = f"{worker_id:040x}"
            with w_conn:
                w_conn.execute(
                    "INSERT INTO swe_gate_repositories (repo_id, repo_name) VALUES (?, ?)",
                    (repo_id, f"org/repo-{worker_id}"),
                )
                if worker_id % 2 == 0:
                    w_conn.execute(
                        "INSERT INTO swe_gate_patch_evaluations "
                        "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
                        "VALUES (?, ?, ?, 1, 'ALLOW_MERGE', 0)",
                        (eval_id, repo_id, sha),
                    )
                else:
                    viol_id = f"VIO-worker-{worker_id:04d}"
                    w_conn.execute(
                        "INSERT INTO swe_gate_patch_evaluations "
                        "(evaluation_id, repo_id, commit_sha, functional_passed, gate_verdict, violations_count) "
                        "VALUES (?, ?, ?, 1, 'REJECT_ARCHITECTURAL_VIOLATION', 1)",
                        (eval_id, repo_id, sha),
                    )
                    w_conn.execute(
                        "INSERT INTO swe_gate_violation_findings "
                        "(violation_id, evaluation_id, violation_type, symbol_or_file) "
                        "VALUES (?, ?, 'TYPE_IGNORE', ?)",
                        (viol_id, eval_id, f"src/module_{worker_id}.py:42"),
                    )
            w_conn.close()
        except Exception as exc:
            worker_errors.append(exc)

    threads = [threading.Thread(target=thread_worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not worker_errors, f"Thread errors encountered: {worker_errors}"

    check_conn = sqlite3.connect(db_file)
    repo_count = check_conn.execute("SELECT COUNT(*) FROM swe_gate_repositories").fetchone()[0]
    eval_count = check_conn.execute("SELECT COUNT(*) FROM swe_gate_patch_evaluations").fetchone()[0]
    viol_count = check_conn.execute("SELECT COUNT(*) FROM swe_gate_violation_findings").fetchone()[0]
    fk_check = check_conn.execute("PRAGMA foreign_key_check").fetchall()
    integrity = check_conn.execute("PRAGMA integrity_check").fetchone()[0]
    check_conn.close()

    assert repo_count == 10
    assert eval_count == 10
    assert viol_count == 5
    assert fk_check == []
    assert integrity == "ok"
