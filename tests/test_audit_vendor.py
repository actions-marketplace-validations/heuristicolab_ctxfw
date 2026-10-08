"""Gate G9 for ctxfw.audit: vendored TraceKit blueprint files must stay byte-for-byte sealed.

manifest_hash: 9cb40e606b107d1ed46d713655e7baef8565d0fb22e824ecda90e90eb82ef3d3
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys

import pytest

from ctxfw.audit import CONTRACTS_PATH, MANIFEST_PATH, SCHEMA_PATH, load_schema_sql

BLUEPRINT_MANIFEST_HASH = "7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c"


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_manifest_is_the_sealed_tracekit_manifest():
    manifest = _manifest()
    assert manifest["signal_id"] == "SIG-728856af9bd65ae0"
    assert manifest["ctxfw"]["status"] == "VERIFIED"
    assert manifest["ctxfw"]["manifest_hash"] == BLUEPRINT_MANIFEST_HASH
    assert manifest["hermetic_compiler"]["passed_tests"] == 49


def test_vendored_contracts_and_schema_match_sealed_sha256():
    deliverables = _manifest()["deliverables"]
    assert _sha256(CONTRACTS_PATH) == deliverables["specs/2_pydantic_contracts.py"]["sha256"]
    assert _sha256(SCHEMA_PATH) == deliverables["specs/3_schema_ddl.sql"]["sha256"]


def test_vendored_files_carry_the_blueprint_hash_header():
    assert BLUEPRINT_MANIFEST_HASH in CONTRACTS_PATH.read_text(encoding="utf-8")
    assert BLUEPRINT_MANIFEST_HASH in load_schema_sql()


def test_vendored_files_have_no_crlf():
    for path in (CONTRACTS_PATH, SCHEMA_PATH, MANIFEST_PATH):
        assert b"\r" not in path.read_bytes(), f"{path.name} was rewritten with CR (line-ending drift)"


def test_audit_package_import_is_lazy():
    code = (
        "import sys, ctxfw.audit;"
        "print([m for m in sys.modules if m=='ctxfw.audit.contracts'])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_vendored_contracts_are_importable_and_total():
    from ctxfw.audit import contracts as tk

    genesis = tk.derive_genesis_hash("SES-test1234")
    assert len(genesis) == 64
    assert tk.LedgerState.REJECTED_INVALID in tk.TERMINAL_STATES
    # delta is total: unknown input collapses to the terminal reject state
    assert tk.transition("garbage", "garbage") is tk.LedgerState.REJECTED_INVALID


@pytest.mark.skipif(sqlite3.sqlite_version_info < (3, 37, 0), reason="sealed DDL requires SQLite >= 3.37")
def test_sealed_schema_loads_and_is_append_only():
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(load_schema_sql())
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"tracekit_sessions", "tracekit_audit_blocks", "tracekit_verification_events"} <= tables
        triggers = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert "trg_tracekit_blocks_no_update" in triggers and "trg_tracekit_blocks_tamper_latch" in triggers
        assert len(triggers) == 12
    finally:
        conn.close()
