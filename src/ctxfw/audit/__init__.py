"""ctxfw.audit -- TraceKit vendored blueprint (milestone 4.0-M1).

CTXFW Axiomatic Gateway (this milestone): status VERIFIED | ACI 1.0000
manifest_hash: 5a5339ac310d5ccd6e435f0652f6294ed641815fe5e2a541a6f95c06d35646e6
Sealed blueprint manifest_hash (TraceKit SIG-728856af9bd65ae0, VERIFIED, ACI 1.0000):
    7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c

Vendored, byte-for-byte, from the sealed blueprint (never edited here):
    contracts.py             <- specs/2_pydantic_contracts.py
    schema.sql               <- specs/3_schema_ddl.sql
    blueprint_manifest.json  <- blueprint_manifest.json
``.gitattributes`` pins them as ``-text`` and ``tests/test_audit_vendor.py`` re-checks their SHA-256
against the sealed manifest (gate G9). Any contract change requires a new sealed blueprint.

Implemented on top of the vendored files (step P2, manifest_hash 5a5339ac310d5ccd6e435f0652f6294ed641815fe5e2a541a6f95c06d35646e6):
    sealer.py    pure 283-byte preimage sealing (no clock, no float, no I/O)
    verifier.py  pure backward audit, fail-closed wrapper, latch rule
    store.py     exclusive ``tracekit.db`` (WAL), 12-trigger validation, kernel-governed retry
Native integration: wired into ``ctxfw mcp``/proxy, ``ctxfw trace verify``, and the ``doctor`` anchor backed by an exclusive SQLite WAL ledger.
This package imports nothing at import time (lazy): ``sealer``/``verifier``/``store`` and the pydantic
models in ``contracts`` load only when imported explicitly.
"""
from pathlib import Path

__all__ = ["CONTRACTS_PATH", "MANIFEST_PATH", "PACKAGE_DIR", "SCHEMA_PATH", "load_schema_sql"]

PACKAGE_DIR = Path(__file__).resolve().parent
CONTRACTS_PATH = PACKAGE_DIR / "contracts.py"
SCHEMA_PATH = PACKAGE_DIR / "schema.sql"
MANIFEST_PATH = PACKAGE_DIR / "blueprint_manifest.json"


def load_schema_sql() -> str:
    """Return the sealed DDL text exactly as vendored (UTF-8)."""
    return SCHEMA_PATH.read_text(encoding="utf-8")
