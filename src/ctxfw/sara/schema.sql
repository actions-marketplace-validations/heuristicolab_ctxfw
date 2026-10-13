-- =============================================================================
-- SARA Runtime Authorization :: Relational DDL (SQLite WAL)
-- Signal: SIG-0d2acf53b92882b0 | Proposal: PROP-0d2acf53b92882b0-H2
-- ctxfw manifest_hash: 51d819312f8dd802981a7b7d97b9d6397316738ded76c94161a9f147411c94ea
-- Protocol: CTXFW Axiomatic Gateway (status: VERIFIED, ACI: 1.0000)
--
-- Invariantes aplicadas a nivel de motor (fail-closed):
--   INV-03/07 : tipos estrictos (CHECK typeof) y risk_score en [0.0, 1.0].
--   INV-06    : QUARANTINE_TOOL inmutable; payload en cuarentena solo se elimina
--               por CASCADE desde su registro padre (nunca por DELETE directo).
--   INV-08    : filas de auditoria nunca se actualizan in situ (trigger ABORT).
--   INV-09    : raw_output solo existe en sara_quarantine_payloads; el log
--               unicamente almacena el digest SHA-256.
-- Compatible con SQLite >= 3.35 (sin STRICT tables: tipado via CHECK typeof).
-- =============================================================================
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------------
-- 1. Politicas de autorizacion (lista blanca inmutable, mascara de 32 bits)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sara_authorized_policies (
    policy_id TEXT PRIMARY KEY
        CHECK (typeof(policy_id) = 'text' AND length(policy_id) BETWEEN 8 AND 68 AND policy_id GLOB 'POL-*'),
    tool_name TEXT NOT NULL
        CHECK (typeof(tool_name) = 'text' AND length(tool_name) BETWEEN 2 AND 64),
    policy_mask INTEGER NOT NULL
        CHECK (typeof(policy_mask) = 'integer' AND policy_mask BETWEEN 0 AND 4294967295),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (tool_name, policy_mask)
);

-- -----------------------------------------------------------------------------
-- 2. Bitacora de ejecuciones (solo digest SHA-256, jamas el payload crudo)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sara_tool_execution_logs (
    execution_id TEXT PRIMARY KEY
        CHECK (typeof(execution_id) = 'text' AND length(execution_id) BETWEEN 12 AND 68 AND execution_id GLOB 'EXE-*'),
    tool_name TEXT NOT NULL
        CHECK (typeof(tool_name) = 'text' AND length(tool_name) BETWEEN 2 AND 64),
    observation_sha256 TEXT NOT NULL
        CHECK (typeof(observation_sha256) = 'text'
               AND length(observation_sha256) = 64
               AND observation_sha256 NOT GLOB '*[^0-9a-f]*'),
    risk_score REAL NOT NULL
        CHECK (typeof(risk_score) IN ('real', 'integer') AND risk_score >= 0.0 AND risk_score <= 1.0),
    verdict TEXT NOT NULL
        CHECK (verdict IN ('ALLOW', 'STRIP_COMMANDS', 'QUARANTINE_TOOL')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- -----------------------------------------------------------------------------
-- 3. Cuarentena: payload crudo aislado, ligado 1:1 a un veredicto QUARANTINE_TOOL
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sara_quarantine_payloads (
    quarantine_id TEXT PRIMARY KEY
        CHECK (typeof(quarantine_id) = 'text' AND length(quarantine_id) BETWEEN 8 AND 68 AND quarantine_id GLOB 'QRN-*'),
    execution_id TEXT NOT NULL UNIQUE
        REFERENCES sara_tool_execution_logs (execution_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    raw_output TEXT NOT NULL
        CHECK (typeof(raw_output) = 'text' AND length(raw_output) <= 65536),
    violation_reason TEXT NOT NULL
        CHECK (typeof(violation_reason) = 'text' AND length(violation_reason) BETWEEN 1 AND 512),
    isolated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- -----------------------------------------------------------------------------
-- 4. Indices compuestos de auditoria (tool_name + verdict)
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_sara_logs_tool_verdict_time
    ON sara_tool_execution_logs (tool_name, verdict, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sara_logs_verdict_risk
    ON sara_tool_execution_logs (verdict, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_sara_policies_tool_mask
    ON sara_authorized_policies (tool_name, policy_mask);
CREATE INDEX IF NOT EXISTS idx_sara_quarantine_isolated
    ON sara_quarantine_payloads (isolated_at DESC);

-- -----------------------------------------------------------------------------
-- 5. Triggers de inmutabilidad y confinamiento (fail-closed)
-- -----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_sara_logs_no_update
BEFORE UPDATE ON sara_tool_execution_logs
BEGIN
    SELECT RAISE(ABORT, 'SARA_INV_08: audit rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_sara_quarantine_no_update
BEFORE UPDATE ON sara_quarantine_payloads
BEGIN
    SELECT RAISE(ABORT, 'SARA_INV_06: quarantined payloads are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_sara_policies_no_update
BEFORE UPDATE ON sara_authorized_policies
BEGIN
    SELECT RAISE(ABORT, 'SARA_INV_04: allowlist policies are immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_sara_quarantine_requires_verdict
BEFORE INSERT ON sara_quarantine_payloads
WHEN COALESCE((SELECT verdict FROM sara_tool_execution_logs WHERE execution_id = NEW.execution_id), '') <> 'QUARANTINE_TOOL'
BEGIN
    SELECT RAISE(ABORT, 'SARA_INV_09: raw_output may only be stored for QUARANTINE_TOOL verdicts');
END;

CREATE TRIGGER IF NOT EXISTS trg_sara_quarantine_no_direct_delete
BEFORE DELETE ON sara_quarantine_payloads
WHEN EXISTS (SELECT 1 FROM sara_tool_execution_logs WHERE execution_id = OLD.execution_id)
BEGIN
    SELECT RAISE(ABORT, 'SARA_INV_06: quarantined payloads are removable only by cascade from the parent log');
END;
