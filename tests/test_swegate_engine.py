# manifest_hash: ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
"""
SWE-Gate Sovereign Engines Conformance & Integration Test Suite (M4-P2)
=======================================================================
Signal   : SIG-673052a2a791ec2b
Proposal : PROP-673052a2a791ec2b-H1
Horizon  : HORIZON_1
M4-P2 manifest_hash:
    ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c
Sealed blueprint manifest_hash (VERIFIED, ACI 1.0000):
    8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f

Validates:
  1. Manifest hash header, zero-CRLF discipline, lazy exports, and AST purity
     sentinel for inspector.py and gate.py.
  2. Pydantic v2 DTO contracts, bounds, pattern validators, and helpers.
  3. SweGateInspector / ReferenceInspector lexical unified-diff parser,
     cyclomatic decision counter, type-ignore detector, and import scanner.
  4. SweGateVerifier / evaluate_patch paper dilemma scenarios, deterministic
     ordering, 256 violation cap, 20,000 diff line limit, and fail-closed
     degradation on garbage inputs.
  5. Static inspection latency micro-benchmark (25 iterations of a 500-line diff
     with median < 5.0 ms).
  6. Transactional SQLite WAL persistence (persist_evaluation, persist_with_retry,
     SweGateStore, SweGateAuditSink) and 10-thread concurrent contention.
"""
from __future__ import annotations

import ast
import re
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Tuple

import pytest
from pydantic import ValidationError

from ctxfw.swegate import (
    COMMIT_SHA_LEN,
    CYCLOMATIC_DELTA_MAX,
    CYCLOMATIC_DELTA_MIN,
    DIFF_LINES_MAX,
    DIFF_SIZE_MAX,
    DIFF_SIZE_MIN,
    DISALLOWED_MODULES_MAX,
    EVALUATION_ID_PATTERN,
    FAILURE_DISPOSITION,
    FAILURE_ROUTING,
    GATE_VERDICT_TO_TERMINAL,
    INSPECTION_LATENCY_BUDGET_MS,
    MAX_CYCLOMATIC_DELTA_MAX,
    MAX_CYCLOMATIC_DELTA_MIN,
    MODULE_NAME_MAX,
    MODULE_NAME_PATTERN,
    PACKAGE_DIR,
    PR_ID_MAX,
    PR_ID_MIN,
    REPO_ID_PATTERN,
    RULE_ID_PATTERN,
    TERMINAL_STATES,
    TESTS_COUNT_MAX,
    TESTS_COUNT_MIN,
    TRANSITION_TABLE,
    VIOLATION_ENTRY_MAX,
    VIOLATION_ENTRY_PATTERN,
    VIOLATION_ID_PATTERN,
    VIOLATION_LOCATION_MAX,
    VIOLATIONS_MAX,
    WAL_RETRY_ATTEMPTS_MAX,
    ArchitecturalConstraintRuleDTO,
    AuthorKind,
    FailureClass,
    FunctionalTestResultDTO,
    FunctionalVerdict,
    GateEvent,
    GateState,
    GateVerdict,
    PatchInspectionAuditDTO,
    PatchMetadataDTO,
    ReferenceInspector,
    SweGateAuditSink,
    SweGateBaseDTO,
    SweGateInspector,
    SweGateStore,
    SweGateVerifier,
    ViolationType,
    classify_failure,
    count_decisions,
    decide_gate_verdict,
    derive_gate_id,
    evaluate_patch,
    extract_imports,
    format_violation,
    inspect_patch,
    load_schema_sql,
    parse_diff,
    persist_evaluation,
    persist_with_retry,
    sha256_hex,
    split_violation,
    transition,
)

EXPECTED_M4_P2_HASH = "ebc799476bea4d97c21b2118259a632ab897ac4572d75abcaaa91d066de0e83c"
BLUEPRINT_MANIFEST_HASH = "8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f"
VALID_SHA = "0123456789abcdef0123456789abcdef01234567"


def _make_meta(
    diff_text: str,
    *,
    commit_sha: str = VALID_SHA,
    author_kind: AuthorKind = AuthorKind.AGENT,
    pr_id: int = 42,
) -> PatchMetadataDTO:
    return PatchMetadataDTO(
        commit_sha=commit_sha,
        author_kind=author_kind,
        pr_id=pr_id,
        diff_size_bytes=len(diff_text.encode("utf-8")),
    )


def _make_rule(
    *,
    rule_id: str = "RULE-arch0001",
    max_cyclomatic_delta: int = 5,
    forbid_type_ignores: bool = True,
    disallowed_import_modules: Tuple[str, ...] = ("requests", "subprocess", "socket"),
) -> ArchitecturalConstraintRuleDTO:
    return ArchitecturalConstraintRuleDTO(
        rule_id=rule_id,
        max_cyclomatic_delta=max_cyclomatic_delta,
        forbid_type_ignores=forbid_type_ignores,
        disallowed_import_modules=disallowed_import_modules,
    )


def _make_functional_pass(passed: int = 644) -> FunctionalTestResultDTO:
    return FunctionalTestResultDTO(
        tests_passed=passed,
        tests_failed=0,
        functional_verdict=FunctionalVerdict.PASSED,
    )


def _make_functional_fail(passed: int = 640, failed: int = 4) -> FunctionalTestResultDTO:
    return FunctionalTestResultDTO(
        tests_passed=passed,
        tests_failed=failed,
        functional_verdict=FunctionalVerdict.FAILED,
    )


# ============================================================================
# 1. Manifest Hash, Zero-CRLF, Lazy Imports & Static AST Purity Sentinel
# ============================================================================
def test_m4_p2_files_carry_manifest_hash_and_zero_crlf():
    m4_p2_files = [
        PACKAGE_DIR / "__init__.py",
        PACKAGE_DIR / "inspector.py",
        PACKAGE_DIR / "gate.py",
        PACKAGE_DIR / "store.py",
        PACKAGE_DIR / "audit.py",
        Path(__file__).resolve(),
        Path(__file__).resolve().parent / "test_swegate_vendor.py",
    ]
    expected_header = f"# manifest_hash: {EXPECTED_M4_P2_HASH}"
    for path in m4_p2_files:
        raw_bytes = path.read_bytes()
        assert b"\r" not in raw_bytes, f"{path.name} contains CR bytes (CRLF drift)"
        text = raw_bytes.decode("utf-8")
        first_line = text.splitlines()[0]
        assert first_line == expected_header, f"{path.name} missing M4-P2 manifest_hash on line 1"
        if path.parent == PACKAGE_DIR:
            assert BLUEPRINT_MANIFEST_HASH in text, f"{path.name} docstring missing blueprint manifest_hash"


def test_lazy_export_of_swegate_engines_and_submodules():
    code = (
        "import sys, ctxfw.swegate as g;"
        "assert 'ctxfw.swegate.contracts' not in sys.modules;"
        "assert 'ctxfw.swegate.inspector' not in sys.modules;"
        "assert 'ctxfw.swegate.gate' not in sys.modules;"
        "assert 'ctxfw.swegate.store' not in sys.modules;"
        "assert 'ctxfw.swegate.audit' not in sys.modules;"
        "assert g.SweGateInspector is g.inspector.SweGateInspector;"
        "assert g.ReferenceInspector is g.SweGateInspector;"
        "assert g.parse_diff is g.SweGateInspector.parse;"
        "assert g.count_decisions is g.SweGateInspector.decisions;"
        "assert g.extract_imports is g.SweGateInspector.imports;"
        "assert g.inspect_patch == g.SweGateInspector.inspect;"
        "assert g.SweGateVerifier is g.gate.SweGateVerifier;"
        "assert g.evaluate_patch is g.gate.evaluate_patch;"
        "assert g.SweGateStore is g.store.SweGateStore;"
        "assert g.SweGateAuditSink is g.audit.SweGateAuditSink;"
        "assert g.SweGateAuditSink is g.SweGateStore;"
        "assert g.persist_evaluation is g.store.persist_evaluation;"
        "assert g.persist_with_retry is g.store.persist_with_retry;"
        "print('SWEGATE_LAZY_OK')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "SWEGATE_LAZY_OK"


def test_ast_purity_sentinel_for_inspector_and_gate():
    forbidden_modules = {
        "ast",
        "importlib",
        "subprocess",
        "os",
        "socket",
        "urllib",
        "requests",
        "httpx",
        "random",
        "secrets",
        "time",
        "datetime",
        "pathlib",
        "sqlite3",
    }
    forbidden_calls = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
    }

    for module_name in ("inspector.py", "gate.py"):
        source = (PACKAGE_DIR / module_name).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=module_name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in forbidden_modules, f"{module_name} imports forbidden module {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    assert top not in forbidden_modules, f"{module_name} imports from forbidden module {node.module}"
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_calls, (
                        f"{module_name} calls forbidden builtin {node.func.id}"
                    )
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in {"parse", "system", "popen", "import_module"} or (
                        isinstance(node.func.value, ast.Name) and node.func.value.id == "cls"
                    ), f"{module_name} calls forbidden attribute {node.func.attr}"


# ============================================================================
# 2. DTO Conformance, Domain Bounds & Deterministic Helpers
# ============================================================================
def test_dto_immutability_and_extra_forbid():
    meta = PatchMetadataDTO(
        commit_sha=VALID_SHA,
        author_kind=AuthorKind.AGENT,
        pr_id=1,
        diff_size_bytes=128,
    )
    assert isinstance(meta, SweGateBaseDTO)
    with pytest.raises(ValidationError):
        meta.pr_id = 99  # type: ignore[misc]
    with pytest.raises(ValidationError):
        PatchMetadataDTO(
            commit_sha=VALID_SHA,
            author_kind=AuthorKind.AGENT,
            pr_id=1,
            diff_size_bytes=128,
            undeclared="x",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "bad_sha",
    [
        "",
        "a" * 39,
        "a" * 41,
        "A" * 40,
        "g" * 40,
        "0123456789abcdef0123456789abcdef0123456Z",
    ],
)
def test_commit_sha_bounds(bad_sha: str):
    assert COMMIT_SHA_LEN == 40
    with pytest.raises(ValidationError):
        PatchMetadataDTO(
            commit_sha=bad_sha,
            author_kind=AuthorKind.HUMAN,
            pr_id=1,
            diff_size_bytes=10,
        )


def test_pr_id_and_diff_size_bounds_and_author_kind():
    p_min = PatchMetadataDTO(
        commit_sha=VALID_SHA,
        author_kind=AuthorKind.HUMAN,
        pr_id=PR_ID_MIN,
        diff_size_bytes=DIFF_SIZE_MIN,
    )
    p_max = PatchMetadataDTO(
        commit_sha=VALID_SHA,
        author_kind=AuthorKind.AGENT,
        pr_id=PR_ID_MAX,
        diff_size_bytes=DIFF_SIZE_MAX,
    )
    assert p_min.author_kind is AuthorKind.HUMAN
    assert p_max.author_kind is AuthorKind.AGENT

    for bad_pr in (0, -1, PR_ID_MAX + 1, True):
        with pytest.raises(ValidationError):
            PatchMetadataDTO(
                commit_sha=VALID_SHA,
                author_kind=AuthorKind.AGENT,
                pr_id=bad_pr,  # type: ignore[arg-type]
                diff_size_bytes=10,
            )

    for bad_size in (0, -1, DIFF_SIZE_MAX + 1, False):
        with pytest.raises(ValidationError):
            PatchMetadataDTO(
                commit_sha=VALID_SHA,
                author_kind=AuthorKind.AGENT,
                pr_id=1,
                diff_size_bytes=bad_size,  # type: ignore[arg-type]
            )


def test_functional_test_result_dto_counter_invariants():
    passed = FunctionalTestResultDTO(
        tests_passed=1,
        tests_failed=0,
        functional_verdict=FunctionalVerdict.PASSED,
    )
    assert passed.tests_passed == 1

    failed_with_failures = FunctionalTestResultDTO(
        tests_passed=643,
        tests_failed=1,
        functional_verdict=FunctionalVerdict.FAILED,
    )
    assert failed_with_failures.functional_verdict is FunctionalVerdict.FAILED

    failed_zero_tests = FunctionalTestResultDTO(
        tests_passed=0,
        tests_failed=0,
        functional_verdict=FunctionalVerdict.FAILED,
    )
    assert failed_zero_tests.functional_verdict is FunctionalVerdict.FAILED

    for tp, tf, verdict in [
        (0, 0, FunctionalVerdict.PASSED),
        (10, 1, FunctionalVerdict.PASSED),
        (10, 0, FunctionalVerdict.FAILED),
        (-1, 0, FunctionalVerdict.FAILED),
        (TESTS_COUNT_MAX + 1, 0, FunctionalVerdict.PASSED),
        (TESTS_COUNT_MIN, -1, FunctionalVerdict.FAILED),
    ]:
        with pytest.raises(ValidationError):
            FunctionalTestResultDTO(
                tests_passed=tp,
                tests_failed=tf,
                functional_verdict=verdict,
            )


def test_architectural_constraint_rule_dto_bounds_and_uniqueness():
    rule = ArchitecturalConstraintRuleDTO(
        rule_id="RULE-valid_01",
        max_cyclomatic_delta=MAX_CYCLOMATIC_DELTA_MIN,
        forbid_type_ignores=True,
        disallowed_import_modules=("os.path", "requests"),
    )
    assert rule.max_cyclomatic_delta == 0

    rule_max = ArchitecturalConstraintRuleDTO(
        rule_id="RULE-valid_02",
        max_cyclomatic_delta=MAX_CYCLOMATIC_DELTA_MAX,
        forbid_type_ignores=False,
        disallowed_import_modules=tuple(f"pkg_{i}" for i in range(DISALLOWED_MODULES_MAX)),
    )
    assert len(rule_max.disallowed_import_modules) == DISALLOWED_MODULES_MAX

    # Duplicate modules forbidden
    with pytest.raises(ValidationError):
        ArchitecturalConstraintRuleDTO(
            rule_id="RULE-dup0001",
            max_cyclomatic_delta=5,
            forbid_type_ignores=True,
            disallowed_import_modules=("requests", "requests"),
        )

    # Bad module names forbidden
    for bad_mod in ("", "1bad", "a..b", ".rel", "rel.", "bad-name", "m" * (MODULE_NAME_MAX + 1)):
        with pytest.raises(ValidationError):
            ArchitecturalConstraintRuleDTO(
                rule_id="RULE-badmod1",
                max_cyclomatic_delta=5,
                forbid_type_ignores=True,
                disallowed_import_modules=(bad_mod,),
            )


def test_identifier_patterns_and_audit_dto_consistency():
    for pattern, sample in [
        (REPO_ID_PATTERN, derive_gate_id("REPO-", "heuristico/ctxfw")),
        (EVALUATION_ID_PATTERN, derive_gate_id("EVL-", "REPO-1234", VALID_SHA, 0)),
        (VIOLATION_ID_PATTERN, derive_gate_id("VIO-", "EVL-1234", 0)),
        (RULE_ID_PATTERN, derive_gate_id("RULE-", "default")),
        (MODULE_NAME_PATTERN, "urllib.request"),
        (VIOLATION_ENTRY_PATTERN, "TYPE_IGNORE|src/app.py:12"),
    ]:
        assert re.fullmatch(pattern, sample) is not None

    assert CYCLOMATIC_DELTA_MIN == -1_000_000
    assert CYCLOMATIC_DELTA_MAX == 1_000_000
    assert VIOLATION_ENTRY_MAX == 500
    assert VIOLATION_LOCATION_MAX == 480

    # Truth table for decide_gate_verdict
    v_sample = format_violation(ViolationType.TYPE_IGNORE, "a.py:1")
    assert decide_gate_verdict(True, ()) is GateVerdict.ALLOW_MERGE
    assert decide_gate_verdict(False, ()) is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert decide_gate_verdict(True, (v_sample,)) is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert decide_gate_verdict(False, (v_sample,)) is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION

    # Format / split roundtrip
    for vtype in ViolationType:
        formatted = format_violation(vtype, "pkg/mod.py:99")
        parsed_type, parsed_loc = split_violation(formatted)
        assert parsed_type is vtype
        assert parsed_loc == "pkg/mod.py:99"

    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# ============================================================================
# 3. Unified Diff Parsing & Cyclomatic Complexity Delta
# ============================================================================
def test_unified_diff_parsing_line_numbers_and_no_newline_marker():
    diff_text = (
        "diff --git a/src/foo.py b/src/foo.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/src/foo.py\n"
        "+++ b/src/foo.py\n"
        "@@ -10,2 +10,4 @@ def f(x):\n"
        "     y = x + 1\n"
        "-    return y\n"
        "+    if y > 0:\n"
        "+        return y\n"
        "+    return 0\n"
        "\\ No newline at end of file\n"
    )
    parsed = parse_diff(diff_text)
    assert len(parsed) == 1
    path, added, removed = parsed[0]
    assert path == "src/foo.py"
    assert removed == [(11, "    return y")]
    assert added == [
        (11, "    if y > 0:"),
        (12, "        return y"),
        (13, "    return 0"),
    ]


@pytest.mark.parametrize(
    "empty_diff",
    ["", "   ", "\n\n", "\t  \n"],
)
def test_parse_diff_rejects_empty_or_whitespace(empty_diff: str):
    with pytest.raises(ValueError, match="DIFF_EMPTY"):
        SweGateInspector.parse(empty_diff)


@pytest.mark.parametrize(
    "malformed_diff",
    [
        12345,  # non-str
        "@@ -1,1 +1,1 @@\n+orphan_hunk = 1\n",  # hunk before header
        "--- a/src/a.py\n+++ b/src/a.py\n",  # header with zero hunks
        "--- /dev/null\n+++ /dev/null\n@@ -1,1 +1,1 @@\n+x = 1\n",  # both /dev/null
        "--- a/src/a.py\n+++ b/src/a.py\n@@ -1,2 +1,2 @@\n+only_one_line\n",  # truncated hunk
        "--- a/src/a.py\n+++ b/src/a.py\n@@ -1,1 +1,1 @@\n!invalid_tag\n",  # invalid hunk tag
        "--- a/src/a.py\n+++ b/src/a.py\n@@ -1,1 +1,1 @@\n+line1\n+extra_added\n-line1\n",  # new_left < 0
        "random garbage outside hunk\n",
    ],
)
def test_parse_diff_rejects_malformed_structures(malformed_diff):
    with pytest.raises(ValueError, match="DIFF_MALFORMED"):
        SweGateInspector.parse(malformed_diff)  # type: ignore[arg-type]


def test_inspect_validates_utf8_byte_size_vs_char_count():
    # Multi-byte UTF-8 characters: byte count > char count
    diff_text = (
        "--- a/src/unicode_mod.py\n"
        "+++ b/src/unicode_mod.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-msg = 'hola'\n"
        "+msg = 'piñata 🚀'\n"
    )
    char_len = len(diff_text)
    byte_len = len(diff_text.encode("utf-8"))
    assert byte_len > char_len

    meta_wrong = PatchMetadataDTO(
        commit_sha=VALID_SHA,
        author_kind=AuthorKind.AGENT,
        pr_id=7,
        diff_size_bytes=char_len,
    )
    rule = _make_rule()
    with pytest.raises(ValueError, match="DIFF_SIZE_MISMATCH"):
        SweGateInspector.inspect(meta_wrong, rule, diff_text)

    meta_exact = _make_meta(diff_text)
    delta, violations = SweGateInspector.inspect(meta_exact, rule, diff_text)
    assert delta == 0
    assert violations == ()


def test_non_python_files_are_skipped_and_deleted_python_file_lowers_complexity():
    diff_text = (
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,2 @@\n"
        " # Title\n"
        "+import requests  # type: ignore\n"
        "--- a/src/legacy.py\n"
        "+++ /dev/null\n"
        "@@ -1,3 +0,0 @@\n"
        "-def old(x):\n"
        "-    if x and x > 1:\n"
        "-        return x\n"
    )
    meta = _make_meta(diff_text)
    rule = _make_rule(max_cyclomatic_delta=0)
    delta, violations = inspect_patch(meta, rule, diff_text)
    # README.md is ignored; legacy.py removed 2 decision points ('if' and 'and')
    assert delta == -2
    assert violations == ()


def test_decisions_counting_and_string_comment_stripping():
    assert count_decisions("x = 1") == 0
    assert count_decisions("if a and b or c:") == 3
    assert count_decisions("elif x:") == 1
    assert count_decisions("for item in items:") == 1
    assert count_decisions("while running:") == 1
    assert count_decisions("except ValueError:") == 1
    assert count_decisions("    case 42:") == 1
    assert count_decisions("    case _ if x > 0:") == 2
    # Keywords inside string literals or trailing comments must not count
    assert count_decisions('msg = "if elif for while except and or"  # if and or while') == 0
    assert count_decisions("msg = 'case 1:' # case 2:") == 0


# ============================================================================
# 4. Paper Dilemma Scenarios & CI Gate Verdicts
# ============================================================================
def test_dilemma_type_ignore_rejected_despite_644_green_tests():
    diff_text = (
        "--- a/src/service.py\n"
        "+++ b/src/service.py\n"
        "@@ -10,1 +10,1 @@\n"
        "-    return compute(x)\n"
        "+    return compute(x)  # type: ignore[arg-type]\n"
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_pass(644)
    rule = _make_rule()

    audit, trace = evaluate_patch(meta, functional, rule, diff_text)
    assert audit.is_functional_passed is True
    assert audit.cyclomatic_delta == 0
    assert audit.architectural_violations == ("TYPE_IGNORE|src/service.py:10",)
    assert audit.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert trace == [
        GateState.RECEIVED,
        GateState.PATCH_INGESTED,
        GateState.REPORT_INGESTED,
        GateState.INSPECTED,
        GateState.DECIDED_REJECT,
    ]


def test_dilemma_cyclomatic_complexity_budget_exceeded_rejected():
    diff_text = (
        "--- a/src/router.py\n"
        "+++ b/src/router.py\n"
        "@@ -1,1 +1,4 @@\n"
        " def route(a, b, c, d):\n"
        "+    if a and b or c:\n"
        "+        while d:\n"
        "+            return 1\n"
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_pass(644)
    rule = _make_rule(max_cyclomatic_delta=2)

    audit, trace = SweGateVerifier.evaluate_traced(meta, functional, rule, diff_text)
    assert audit.is_functional_passed is True
    assert audit.cyclomatic_delta == 4
    assert audit.architectural_violations == ("CYCLOMATIC_DELTA|total:4>2",)
    assert audit.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert trace[-1] is GateState.DECIDED_REJECT


def test_dilemma_disallowed_imports_static_and_dynamic_rejected():
    diff_text = (
        "--- a/src/net.py\n"
        "+++ b/src/net.py\n"
        "@@ -1,1 +1,6 @@\n"
        " import sys\n"
        "+import requests\n"
        "+from requests.adapters import HTTPAdapter\n"
        "+import os, requests as r\n"
        '+m1 = importlib.import_module("requests.auth")\n'
        '+m2 = __import__("requests")\n'
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_pass(100)
    rule = _make_rule(disallowed_import_modules=("requests",))

    audit = SweGateVerifier.evaluate(meta, functional, rule, diff_text)
    assert audit.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert audit.architectural_violations == (
        "DISALLOWED_IMPORT|requests@src/net.py:2",
        "DISALLOWED_IMPORT|requests.adapters@src/net.py:3",
        "DISALLOWED_IMPORT|requests@src/net.py:4",
        "DISALLOWED_IMPORT|requests.auth@src/net.py:5",
        "DISALLOWED_IMPORT|requests@src/net.py:6",
    )


def test_similar_module_names_and_relative_imports_allowed():
    diff_text = (
        "--- a/src/ internal.py\n"
        "+++ b/src/internal.py\n"
        "@@ -1,1 +1,5 @@\n"
        " import sys\n"
        "+import requestsx\n"
        "+import my_requests\n"
        "+from . import requests\n"
        "+from .requests import helper\n"
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_pass(50)
    rule = _make_rule(disallowed_import_modules=("requests",))

    assert extract_imports("from . import requests") == []
    assert extract_imports("from .requests import helper") == []

    audit, trace = evaluate_patch(meta, functional, rule, diff_text)
    assert audit.architectural_violations == ()
    assert audit.gate_verdict is GateVerdict.ALLOW_MERGE
    assert trace == [
        GateState.RECEIVED,
        GateState.PATCH_INGESTED,
        GateState.REPORT_INGESTED,
        GateState.INSPECTED,
        GateState.DECIDED_PASS,
    ]


def test_functional_failure_with_clean_patch_rejected():
    diff_text = (
        "--- a/src/clean.py\n"
        "+++ b/src/clean.py\n"
        "@@ -1,1 +1,2 @@\n"
        " def add(a, b):\n"
        "+    return a + b\n"
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_fail(passed=10, failed=1)
    rule = _make_rule()

    audit, trace = evaluate_patch(meta, functional, rule, diff_text)
    assert audit.is_functional_passed is False
    assert audit.architectural_violations == ()
    assert audit.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert trace[-1] is GateState.DECIDED_REJECT


def test_type_ignore_allowed_when_rule_permits_and_removed_or_context_ignored():
    diff_text = (
        "--- a/src/typing_mod.py\n"
        "+++ b/src/typing_mod.py\n"
        "@@ -1,3 +1,3 @@\n"
        " x = 1  # type: ignore\n"
        "-y = 2  # type: ignore\n"
        "+y = 2\n"
        " z = 3\n"
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_pass(10)
    rule_strict = _make_rule(forbid_type_ignores=True)
    audit_strict, _ = evaluate_patch(meta, functional, rule_strict, diff_text)
    assert audit_strict.architectural_violations == ()
    assert audit_strict.gate_verdict is GateVerdict.ALLOW_MERGE

    # Added # type: ignore when forbid_type_ignores=False -> allowed
    diff_added_ti = (
        "--- a/src/typing_mod.py\n"
        "+++ b/src/typing_mod.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-y = 2\n"
        "+y = 2  # type: ignore\n"
    )
    meta2 = _make_meta(diff_added_ti)
    rule_permissive = _make_rule(forbid_type_ignores=False)
    audit_perm, _ = evaluate_patch(meta2, functional, rule_permissive, diff_added_ti)
    assert audit_perm.architectural_violations == ()
    assert audit_perm.gate_verdict is GateVerdict.ALLOW_MERGE


def test_violation_ordering_deduplication_and_cap_256():
    # Order: TYPE_IGNORE first, then DISALLOWED_IMPORT in diff order, then CYCLOMATIC_DELTA
    diff_text = (
        "--- a/src/order.py\n"
        "+++ b/src/order.py\n"
        "@@ -1,1 +1,3 @@\n"
        " x = 0\n"
        "+import requests  # type: ignore\n"
        "+if x and x > 1:\n"
    )
    meta = _make_meta(diff_text)
    rule = _make_rule(max_cyclomatic_delta=1, disallowed_import_modules=("requests",))
    delta, violations = ReferenceInspector.inspect(meta, rule, diff_text)
    assert delta == 2
    assert violations == (
        "TYPE_IGNORE|src/order.py:2",
        "DISALLOWED_IMPORT|requests@src/order.py:2",
        "CYCLOMATIC_DELTA|total:2>1",
    )

    # Cap at 256 violations when more than 256 lines introduce violations
    added_lines = "\n".join(f"+x_{i} = {i}  # type: ignore" for i in range(300))
    big_diff = (
        "--- a/src/many.py\n"
        "+++ b/src/many.py\n"
        "@@ -1,1 +1,301 @@\n"
        " base = 0\n"
        f"{added_lines}\n"
    )
    big_meta = _make_meta(big_diff)
    audit_big, _ = evaluate_patch(big_meta, _make_functional_pass(), rule, big_diff)
    assert len(audit_big.architectural_violations) == VIOLATIONS_MAX == 256
    assert audit_big.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION


def test_diff_lines_max_20000_boundary():
    # 4 header lines + 19,996 added lines = 20,000 lines (allowed)
    body_ok = "\n".join(f"+v_{i} = {i}" for i in range(DIFF_LINES_MAX - 4))
    diff_ok = (
        "diff --git a/src/boundary.py b/src/boundary.py\n"
        "--- a/src/boundary.py\n"
        "+++ b/src/boundary.py\n"
        f"@@ -0,0 +1,{DIFF_LINES_MAX - 4} @@\n"
        f"{body_ok}\n"
    )
    meta_ok = _make_meta(diff_ok)
    rule = _make_rule()
    delta, violations = SweGateInspector.inspect(meta_ok, rule, diff_ok)
    assert delta == 0
    assert violations == ()

    # 4 header lines + 19,997 added lines = 20,001 lines (rejected)
    body_over = "\n".join(f"+v_{i} = {i}" for i in range(DIFF_LINES_MAX - 3))
    diff_over = (
        "diff --git a/src/boundary.py b/src/boundary.py\n"
        "--- a/src/boundary.py\n"
        "+++ b/src/boundary.py\n"
        f"@@ -0,0 +1,{DIFF_LINES_MAX - 3} @@\n"
        f"{body_over}\n"
    )
    meta_over = _make_meta(diff_over)
    with pytest.raises(ValueError, match="DIFF_MALFORMED"):
        SweGateInspector.inspect(meta_over, rule, diff_over)

    audit_over, trace_over = evaluate_patch(meta_over, _make_functional_pass(), rule, diff_over)
    assert audit_over.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert audit_over.architectural_violations == ("INVALID_INPUT|patch",)
    assert trace_over[-1] is GateState.REJECTED_INVALID


@pytest.mark.parametrize(
    "bad_args",
    [
        (None, None, None, None),
        (123, _make_functional_pass(), _make_rule(), "diff"),
        (_make_meta("x"), "not_a_functional_dto", _make_rule(), "x"),
        (_make_meta("x"), _make_functional_pass(), "not_a_rule_dto", "x"),
        (_make_meta("x"), _make_functional_pass(), _make_rule(), b"bytes_diff"),
        (_make_meta("x"), _make_functional_pass(), _make_rule(), "size_mismatch_diff"),
    ],
)
def test_evaluate_patch_fail_closed_on_garbage_inputs(bad_args):
    audit, trace = SweGateVerifier.evaluate_fail_closed(*bad_args)
    assert audit.gate_verdict is GateVerdict.REJECT_ARCHITECTURAL_VIOLATION
    assert audit.cyclomatic_delta == 0
    assert audit.architectural_violations == ("INVALID_INPUT|patch",)
    assert trace[-1] is GateState.REJECTED_INVALID


def test_deterministic_inspection_repeatability():
    diff_text = (
        "--- a/src/repeat.py\n"
        "+++ b/src/repeat.py\n"
        "@@ -1,2 +1,4 @@\n"
        " def check(x):\n"
        "-    return x\n"
        "+    import requests  # type: ignore\n"
        "+    if x and x > 0:\n"
        "+        return x\n"
    )
    meta = _make_meta(diff_text)
    functional = _make_functional_pass()
    rule = _make_rule(max_cyclomatic_delta=1)

    baseline = evaluate_patch(meta, functional, rule, diff_text)
    for _ in range(10):
        assert evaluate_patch(meta, functional, rule, diff_text) == baseline


# ============================================================================
# 5. Static Inspection Latency Micro-Benchmark (< 5.0 ms median for 500 lines)
# ============================================================================
def test_static_inspection_latency_budget_500_line_diff():
    hunk_lines = []
    for i in range(1, 497):
        if i % 10 == 0:
            hunk_lines.append(f"+    if x_{i} > 0 and x_{i} < 100:")
        else:
            hunk_lines.append(f"+    x_{i} = {i}")
    diff_500 = (
        "--- a/src/perf_target.py\n"
        "+++ b/src/perf_target.py\n"
        "@@ -1,1 +1,497 @@\n"
        " def perf_fn():\n"
        + "\n".join(hunk_lines)
        + "\n"
    )
    assert len(diff_500.splitlines()) == 500
    meta = _make_meta(diff_500)
    rule = _make_rule(max_cyclomatic_delta=500)

    samples_ms: list[float] = []
    for _ in range(25):
        t0 = time.perf_counter()
        delta, violations = SweGateInspector.inspect(meta, rule, diff_500)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        samples_ms.append(elapsed_ms)
        assert delta == 98
        assert violations == ()

    median_ms = statistics.median(samples_ms)
    assert median_ms < INSPECTION_LATENCY_BUDGET_MS, (
        f"Median inspection latency {median_ms:.3f} ms exceeded {INSPECTION_LATENCY_BUDGET_MS} ms budget"
    )


# ============================================================================
# 6. FSM, SQLite WAL Persistence, Retry Backoff & Concurrent Store Tests
# ============================================================================
def test_persist_evaluation_and_multiple_evaluations_of_same_commit():
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(load_schema_sql())
        repo_id = derive_gate_id("REPO-", "heuristico/ctxfw")
        conn.execute(
            "INSERT INTO swe_gate_repositories (repo_id, repo_name) VALUES (?, ?)",
            (repo_id, "heuristico/ctxfw"),
        )

        diff_text = (
            "--- a/src/mod.py\n"
            "+++ b/src/mod.py\n"
            "@@ -1,1 +1,2 @@\n"
            " x = 1\n"
            "+import requests  # type: ignore\n"
        )
        meta = _make_meta(diff_text)
        audit, _ = evaluate_patch(meta, _make_functional_pass(), _make_rule(), diff_text)

        ev_id_0 = persist_evaluation(conn, repo_id, meta, audit)
        ev_id_1 = persist_evaluation(conn, repo_id, meta, audit)
        assert ev_id_0 != ev_id_1
        assert ev_id_0 == derive_gate_id("EVL-", repo_id, meta.commit_sha, 0)
        assert ev_id_1 == derive_gate_id("EVL-", repo_id, meta.commit_sha, 1)

        findings = conn.execute(
            "SELECT violation_type, symbol_or_file FROM swe_gate_violation_findings "
            "WHERE evaluation_id = ? ORDER BY rowid ASC",
            (ev_id_0,),
        ).fetchall()
        assert findings == [
            ("TYPE_IGNORE", "src/mod.py:2"),
            ("DISALLOWED_IMPORT", "requests@src/mod.py:2"),
        ]
    finally:
        conn.close()


def test_persist_with_retry_recovery_exhaustion_and_non_transient_error():
    # 1. Recovery on 3rd attempt -> naps == [0.02, 0.04], terminal PASS_GATE
    calls = 0

    def flaky_twice() -> None:
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise sqlite3.OperationalError("database is locked")

    slept: list[float] = []
    state_ok, naps_ok = persist_with_retry(
        flaky_twice,
        slept.append,
        GateState.DECIDED_PASS,
    )
    assert state_ok is GateState.PASS_GATE
    assert naps_ok == [0.02, 0.04]
    assert slept == [0.02, 0.04]

    # 2. Exhaustion after 3 attempts -> naps == [0.02, 0.04, 0.08], REJECTED_INVALID
    def always_locked() -> None:
        raise sqlite3.OperationalError("database table is locked")

    slept_ex: list[float] = []
    state_ex, naps_ex = persist_with_retry(
        always_locked,
        slept_ex.append,
        GateState.DECIDED_REJECT,
    )
    assert state_ex is GateState.REJECTED_INVALID
    assert naps_ex == [0.02, 0.04, 0.08]
    assert slept_ex == [0.02, 0.04, 0.08]

    # 3. Non-transient OperationalError propagates immediately without sleeping
    def syntax_err() -> None:
        raise sqlite3.OperationalError("near 'BAD': syntax error")

    slept_err: list[float] = []
    with pytest.raises(sqlite3.OperationalError, match="syntax error"):
        persist_with_retry(syntax_err, slept_err.append, GateState.DECIDED_PASS)
    assert slept_err == []


def test_swegate_store_end_to_end_and_multithreaded_wal(tmp_path: Path):
    db_path = tmp_path / "swegate_store.db"
    with SweGateAuditSink(db_path) as store:
        assert isinstance(store, SweGateStore)
        repo_id = store.register_repository("heuristico/ctxfw")
        # Idempotent registration with same name returns same repo_id
        assert store.register_repository("heuristico/ctxfw", repo_id=repo_id) == repo_id
        # Registration with conflicting name or non-str raises IntegrityError
        with pytest.raises(sqlite3.IntegrityError):
            store.register_repository("other/repo", repo_id=repo_id)
        with pytest.raises(sqlite3.IntegrityError):
            store.register_repository(12345)  # type: ignore[arg-type]

        # Clean patch -> ALLOW_MERGE & PASS_GATE
        clean_diff = (
            "--- a/src/ok.py\n"
            "+++ b/src/ok.py\n"
            "@@ -1,1 +1,2 @@\n"
            " x = 1\n"
            "+y = 2\n"
        )
        meta_clean = _make_meta(clean_diff)
        audit_clean, ev_id_clean, trace_clean = store.evaluate_and_record(
            repo_id,
            meta_clean,
            _make_functional_pass(),
            _make_rule(),
            clean_diff,
        )
        assert audit_clean.gate_verdict is GateVerdict.ALLOW_MERGE
        assert ev_id_clean is not None
        assert trace_clean[-1] is GateState.PASS_GATE
        assert GATE_VERDICT_TO_TERMINAL[audit_clean.gate_verdict] is GateState.PASS_GATE

        # Invalid decided_state passed to record_evaluation must fail closed without persisting
        ev_invalid_state, state_invalid, naps_invalid = store.record_evaluation(
            repo_id,
            meta_clean,
            audit_clean,
            decided_state=GateState.REJECTED_INVALID,
        )
        assert ev_invalid_state is None
        assert state_invalid is GateState.REJECTED_INVALID
        assert naps_invalid == []

        rec = store.get_evaluation(ev_id_clean)
        assert rec is not None
        assert rec["evaluation_id"] == ev_id_clean
        assert rec["repo_id"] == repo_id
        assert rec["commit_sha"] == VALID_SHA
        assert rec["functional_passed"] is True
        assert rec["gate_verdict"] == "ALLOW_MERGE"
        assert rec["violations_count"] == 0
        assert store.get_violations(ev_id_clean) == []
        assert store.get_evaluation("EVL-nonexistent") is None

        # Invalid patch -> fail-closed REJECTED_INVALID without persisting
        audit_bad, ev_id_bad, trace_bad = store.evaluate_and_record(
            repo_id,
            None,
            _make_functional_pass(),
            _make_rule(),
            clean_diff,
        )
        assert ev_id_bad is None
        assert trace_bad == [GateState.RECEIVED, GateState.REJECTED_INVALID]
        assert audit_bad.architectural_violations == ("INVALID_INPUT|patch",)

        # 10 concurrent worker threads recording evaluations into the same store
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                sha = f"{idx + 100:040x}"
                w_diff = (
                    f"--- a/src/w_{idx}.py\n"
                    f"+++ b/src/w_{idx}.py\n"
                    "@@ -1,1 +1,2 @@\n"
                    " a = 1\n"
                    "+import requests  # type: ignore\n"
                )
                w_meta = _make_meta(w_diff, commit_sha=sha, pr_id=idx + 1)
                w_audit, w_trace = evaluate_patch(
                    w_meta, _make_functional_pass(), _make_rule(), w_diff
                )
                ev_id, final_state, _ = store.record_evaluation(
                    repo_id, w_meta, w_audit, decided_state=w_trace[-1]
                )
                assert ev_id is not None
                assert final_state is GateState.REJECT_NON_FUNCTIONAL_REGRESSION
                viols = store.get_violations(ev_id)
                assert len(viols) == 2
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
        assert not errors, f"Concurrent worker errors: {errors}"

        # 5 separate SQLite connections concurrently evaluating the EXACT SAME commit_sha
        same_sha = "f" * 40
        same_meta = _make_meta(clean_diff, commit_sha=same_sha, pr_id=999)
        multi_conn_ids: list[str] = []
        multi_conn_lock = threading.Lock()

        def multi_conn_worker() -> None:
            try:
                with SweGateStore(db_path) as ext_store:
                    r_id = ext_store.register_repository("heuristico/ctxfw")
                    ev_id, f_state, _ = ext_store.record_evaluation(
                        r_id, same_meta, audit_clean
                    )
                    assert ev_id is not None
                    assert f_state is GateState.PASS_GATE
                    with multi_conn_lock:
                        multi_conn_ids.append(ev_id)
            except Exception as exc:
                errors.append(exc)

        mc_threads = [threading.Thread(target=multi_conn_worker) for _ in range(5)]
        for t in mc_threads:
            t.start()
        for t in mc_threads:
            t.join(timeout=10.0)
        assert not errors, f"Multi-connection worker errors: {errors}"
        assert len(set(multi_conn_ids)) == 5


def test_fsm_and_failure_taxonomy_completeness():
    assert len(TRANSITION_TABLE) == 13
    assert len(TERMINAL_STATES) == 3
    for code, fclass in FAILURE_ROUTING.items():
        assert classify_failure(code) is fclass
        assert fclass in FAILURE_DISPOSITION
    for state in TERMINAL_STATES:
        for event in GateEvent:
            assert transition(state, event) is state


def test_single_line_hunk_header_without_comma_counts():
    diff_text = (
        "--- a/src/single.py\n"
        "+++ b/src/single.py\n"
        "@@ -7 +7 @@\n"
        "-old_val = 1\n"
        "+if new_val:\n"
    )
    parsed = parse_diff(diff_text)
    assert parsed == [("src/single.py", [(7, "if new_val:")], [(7, "old_val = 1")])]
    meta = _make_meta(diff_text)
    delta, violations = inspect_patch(meta, _make_rule(), diff_text)
    assert delta == 1
    assert violations == ()


def test_tab_separated_diff_headers_and_blank_context_line():
    diff_text = (
        "--- a/src/tabbed.py\t2026-10-06 00:00:00.000000000 +0000\n"
        "+++ b/src/tabbed.py\t2026-10-06 00:00:01.000000000 +0000\n"
        "@@ -1,3 +1,3 @@\n"
        "\n"
        "-x = 1\n"
        "+x = 2\n"
        " y = 3\n"
    )
    parsed = parse_diff(diff_text)
    assert parsed[0][0] == "src/tabbed.py"
    assert parsed[0][1] == [(2, "x = 2")]
    assert parsed[0][2] == [(2, "x = 1")]


def test_multi_file_multi_hunk_diff_accumulation():
    diff_text = (
        "--- a/src/a.py\n"
        "+++ b/src/a.py\n"
        "@@ -1,1 +1,2 @@\n"
        " x = 0\n"
        "+if x > 0:\n"
        "@@ -20,1 +21,2 @@\n"
        " y = 0\n"
        "+while y < 10:\n"
        "--- a/src/b.py\n"
        "+++ b/src/b.py\n"
        "@@ -5,1 +5,2 @@\n"
        " z = 0\n"
        "+import subprocess  # type: ignore\n"
    )
    meta = _make_meta(diff_text)
    rule = _make_rule(max_cyclomatic_delta=1, disallowed_import_modules=("subprocess",))
    delta, violations = SweGateInspector.inspect(meta, rule, diff_text)
    assert delta == 2
    assert violations == (
        "TYPE_IGNORE|src/b.py:6",
        "DISALLOWED_IMPORT|subprocess@src/b.py:6",
        "CYCLOMATIC_DELTA|total:2>1",
    )


def test_duplicate_violation_on_same_line_is_deduplicated():
    diff_text = (
        "--- a/src/dup.py\n"
        "+++ b/src/dup.py\n"
        "@@ -1,1 +1,2 @@\n"
        " x = 0\n"
        "+import requests, requests\n"
    )
    meta = _make_meta(diff_text)
    rule = _make_rule(disallowed_import_modules=("requests",))
    delta, violations = SweGateInspector.inspect(meta, rule, diff_text)
    assert delta == 0
    assert violations == ("DISALLOWED_IMPORT|requests@src/dup.py:2",)


@pytest.mark.parametrize(
    "passed,violations,bad_verdict",
    [
        (False, (), GateVerdict.ALLOW_MERGE),
        (True, ("TYPE_IGNORE|src/x.py:1",), GateVerdict.ALLOW_MERGE),
        (False, ("TYPE_IGNORE|src/x.py:1",), GateVerdict.ALLOW_MERGE),
        (True, (), GateVerdict.REJECT_ARCHITECTURAL_VIOLATION),
    ],
)
def test_patch_inspection_audit_dto_rejects_inconsistent_verdict(
    passed: bool,
    violations: Tuple[str, ...],
    bad_verdict: GateVerdict,
):
    with pytest.raises(ValidationError):
        PatchInspectionAuditDTO(
            is_functional_passed=passed,
            cyclomatic_delta=0,
            architectural_violations=violations,
            gate_verdict=bad_verdict,
        )


def test_swegate_store_with_external_connection():
    ext_conn = sqlite3.connect(":memory:")
    try:
        store = SweGateStore(ext_conn)
        assert store.connection is ext_conn
        repo_id = store.register_repository("heuristico/external")
        diff_text = (
            "--- a/src/ext.py\n"
            "+++ b/src/ext.py\n"
            "@@ -1,1 +1,2 @@\n"
            " a = 1\n"
            "+b = 2\n"
        )
        meta = _make_meta(diff_text)
        audit, _ = evaluate_patch(meta, _make_functional_pass(), _make_rule(), diff_text)
        ev_id, final_state, naps = store.record_evaluation(repo_id, meta, audit)
        assert ev_id is not None
        assert final_state is GateState.PASS_GATE
        assert naps == []
        store.close()
        # External connection remains open after store.close()
        count = ext_conn.execute("SELECT COUNT(*) FROM swe_gate_patch_evaluations").fetchone()[0]
        assert count == 1
    finally:
        ext_conn.close()


def test_new_file_from_dev_null_uses_new_path():
    diff_text = (
        "diff --git a/src/created.py b/src/created.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/src/created.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+def created(x):\n"
        "+    return x  # type: ignore\n"
    )
    meta = _make_meta(diff_text)
    delta, violations = SweGateInspector.inspect(meta, _make_rule(), diff_text)
    assert delta == 0
    assert violations == ("TYPE_IGNORE|src/created.py:2",)


def test_submodule_prefix_matching_in_disallowed_imports():
    diff_text = (
        "--- a/src/http_client.py\n"
        "+++ b/src/http_client.py\n"
        "@@ -1,1 +1,4 @@\n"
        " import sys\n"
        "+import urllib.parse\n"
        "+import urllib.request\n"
        "+from urllib.request.handlers import BaseHandler\n"
    )
    meta = _make_meta(diff_text)
    rule = _make_rule(disallowed_import_modules=("urllib.request",))
    delta, violations = SweGateInspector.inspect(meta, rule, diff_text)
    assert delta == 0
    assert violations == (
        "DISALLOWED_IMPORT|urllib.request@src/http_client.py:3",
        "DISALLOWED_IMPORT|urllib.request.handlers@src/http_client.py:4",
    )


def test_swegate_verifier_evaluate_and_evaluate_traced_consistency():
    diff_text = (
        "--- a/src/v.py\n"
        "+++ b/src/v.py\n"
        "@@ -1,1 +1,2 @@\n"
        " x = 1\n"
        "+if x:\n"
    )
    meta = _make_meta(diff_text)
    func = _make_functional_pass()
    rule = _make_rule()
    direct = SweGateVerifier.evaluate(meta, func, rule, diff_text)
    traced_dto, trace = SweGateVerifier.evaluate_traced(meta, func, rule, diff_text)
    fc_dto, fc_trace = SweGateVerifier.evaluate_fail_closed(meta, func, rule, diff_text)
    assert direct == traced_dto == fc_dto
    assert trace == fc_trace


