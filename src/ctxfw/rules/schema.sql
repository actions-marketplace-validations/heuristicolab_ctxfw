-- =============================================================================
-- Claude Rules Compiler :: Relational DDL (SQLite WAL)
-- Signal: SIG-1d0a63f087edb904 | Proposal: PROP-1d0a63f087edb904-H2
-- ctxfw manifest_hash: b5b8e1cd10ce8beeed6b076f4726d19b361a6ce2f5d480c2bb2aa437986822d3
-- Protocol: CTXFW Axiomatic Gateway (status: VERIFIED, ACI: 1.0000)
--
-- Invariantes aplicadas a nivel de motor (fail-closed):
--   INV-06 : targets de guard jamas comodin (deny-all) ni vacios.
--   INV-08 : filas de manifiestos, guards y logs son append-only (ABORT en UPDATE);
--            guards y logs solo se eliminan por CASCADE desde su manifiesto padre.
--   INV-09 : guards insertados nunca exceden compiled_rules_count declarado.
-- Jerarquia: compiled_rule_manifests 1 --- N compiled_ast_guards 1 --- N rule_enforcement_logs
-- Compatible con SQLite >= 3.35 (tipado estricto via CHECK typeof, sin STRICT tables).
-- =============================================================================
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------------
-- 1. Manifiestos compilados (uno por version de contenido del archivo de reglas)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compiled_rule_manifests (
    manifest_id TEXT PRIMARY KEY
        CHECK (typeof(manifest_id) = 'text' AND length(manifest_id) BETWEEN 8 AND 68 AND manifest_id GLOB 'MNF-*'),
    source_file_path TEXT NOT NULL
        CHECK (typeof(source_file_path) = 'text' AND length(source_file_path) BETWEEN 1 AND 512),
    file_sha256 TEXT NOT NULL
        CHECK (typeof(file_sha256) = 'text' AND length(file_sha256) = 64 AND file_sha256 NOT GLOB '*[^0-9a-f]*'),
    compiled_rules_count INTEGER NOT NULL
        CHECK (typeof(compiled_rules_count) = 'integer' AND compiled_rules_count BETWEEN 0 AND 256),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (source_file_path, file_sha256)
);

-- -----------------------------------------------------------------------------
-- 2. Guards AST deny deterministas (siempre deny estricto: no existe columna allow)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compiled_ast_guards (
    guard_id TEXT PRIMARY KEY
        CHECK (typeof(guard_id) = 'text' AND length(guard_id) BETWEEN 8 AND 68 AND guard_id GLOB 'GRD-*'),
    manifest_id TEXT NOT NULL
        REFERENCES compiled_rule_manifests (manifest_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    rule_intent TEXT NOT NULL
        CHECK (rule_intent IN ('PATH_DENY', 'COMMAND_DENY', 'AST_DENY', 'IMPORT_DENY')),
    target_expression TEXT NOT NULL
        CHECK (typeof(target_expression) = 'text'
               AND length(target_expression) BETWEEN 1 AND 256
               AND trim(target_expression) NOT IN ('*', '**', '/')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (manifest_id, rule_intent, target_expression)
);

-- -----------------------------------------------------------------------------
-- 3. Bitacora de aplicacion (veredicto de cada evaluacion de tool call)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rule_enforcement_logs (
    log_id TEXT PRIMARY KEY
        CHECK (typeof(log_id) = 'text' AND length(log_id) BETWEEN 8 AND 68 AND log_id GLOB 'LOG-*'),
    guard_id TEXT NOT NULL
        REFERENCES compiled_ast_guards (guard_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    tool_call_attempted TEXT NOT NULL
        CHECK (typeof(tool_call_attempted) = 'text' AND length(tool_call_attempted) BETWEEN 1 AND 4096),
    verdict TEXT NOT NULL
        CHECK (verdict IN ('ALLOW', 'BLOCKED')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- -----------------------------------------------------------------------------
-- 4. Indices de auditoria y de ruta de consulta
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_manifests_source_time
    ON compiled_rule_manifests (source_file_path, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_guards_manifest_intent
    ON compiled_ast_guards (manifest_id, rule_intent);
CREATE INDEX IF NOT EXISTS idx_enforcement_guard_verdict_time
    ON rule_enforcement_logs (guard_id, verdict, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_enforcement_verdict_time
    ON rule_enforcement_logs (verdict, created_at DESC);

-- -----------------------------------------------------------------------------
-- 5. Triggers de inmutabilidad (ABORT en UPDATE) y confinamiento de borrado
-- -----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_manifests_no_update
BEFORE UPDATE ON compiled_rule_manifests
BEGIN
    SELECT RAISE(ABORT, 'RULES_INV_08: compiled manifests are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_guards_no_update
BEFORE UPDATE ON compiled_ast_guards
BEGIN
    SELECT RAISE(ABORT, 'RULES_INV_08: compiled guards are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_enforcement_no_update
BEFORE UPDATE ON rule_enforcement_logs
BEGIN
    SELECT RAISE(ABORT, 'RULES_INV_08: enforcement logs are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_guards_within_declared_count
BEFORE INSERT ON compiled_ast_guards
WHEN (SELECT COUNT(*) FROM compiled_ast_guards WHERE manifest_id = NEW.manifest_id)
     >= COALESCE((SELECT compiled_rules_count FROM compiled_rule_manifests WHERE manifest_id = NEW.manifest_id), 0)
BEGIN
    SELECT RAISE(ABORT, 'RULES_INV_09: guards exceed the declared compiled_rules_count');
END;

CREATE TRIGGER IF NOT EXISTS trg_guards_no_direct_delete
BEFORE DELETE ON compiled_ast_guards
WHEN EXISTS (SELECT 1 FROM compiled_rule_manifests WHERE manifest_id = OLD.manifest_id)
BEGIN
    SELECT RAISE(ABORT, 'RULES_INV_08: guards are removable only by cascade from the parent manifest');
END;

CREATE TRIGGER IF NOT EXISTS trg_enforcement_no_direct_delete
BEFORE DELETE ON rule_enforcement_logs
WHEN EXISTS (SELECT 1 FROM compiled_ast_guards WHERE guard_id = OLD.guard_id)
BEGIN
    SELECT RAISE(ABORT, 'RULES_INV_08: enforcement logs are removable only by cascade from the parent guard');
END;
