-- ============================================================================
-- SWE-GATE CI VERIFIER :: 3_schema_ddl.sql
-- Signal   : SIG-673052a2a791ec2b
-- Proposal : PROP-673052a2a791ec2b-H1
-- Horizon  : HORIZON_1
-- manifest_hash (CTXFW evaluate_spec_axioms, status VERIFIED, ACI 1.0000):
--   8fcfd5d81ee43f9e469b2437c19f95d7657590b7becbc97241a916d86dcb023f
-- Engine   : SQLite >= 3.37 (WAL). Typing is enforced with CHECK(typeof(..)).
-- Ledger   : append-only. UPDATE is always aborted; direct DELETE of child rows
--            is aborted; rows disappear only through ON DELETE CASCADE from
--            swe_gate_repositories (repository -> evaluations -> violations).
-- Verdicts : the persisted verdict names are ALLOW_MERGE and
--            REJECT_ARCHITECTURAL_VIOLATION. A functional failure with zero
--            architectural findings is also persisted as
--            REJECT_ARCHITECTURAL_VIOLATION (no third verdict value exists).
-- Scope    : SQLite cannot parse diffs. The engine enforces format, verdict
--            consistency (ALLOW_MERGE requires functional_passed = 1 and
--            violations_count = 0) and a cap on child rows: the number of
--            violation records of an evaluation never exceeds violations_count.
--            Equality (every violation persisted) is the job of the writer.
-- created_at defaults to the engine clock (UTC, 24 chars, millisecond
-- precision, YYYY-MM-DDTHH:MM:SS.fffZ); callers may supply a canonical value.
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS swe_gate_repositories (
    repo_id    TEXT PRIMARY KEY
        CHECK (typeof(repo_id) = 'text'
               AND length(repo_id) BETWEEN 9 AND 69
               AND repo_id GLOB 'REPO-*'),
    repo_name  TEXT NOT NULL
        CHECK (typeof(repo_name) = 'text'
               AND length(repo_name) BETWEEN 1 AND 200),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (typeof(created_at) = 'text'
               AND length(created_at) = 24
               AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
               AND created_at >= '2020-01-01T00:00:00.000Z'
               AND created_at <  '2100-01-01T00:00:00.000Z')
);

CREATE TABLE IF NOT EXISTS swe_gate_patch_evaluations (
    evaluation_id     TEXT PRIMARY KEY
        CHECK (typeof(evaluation_id) = 'text'
               AND length(evaluation_id) BETWEEN 8 AND 68
               AND evaluation_id GLOB 'EVL-*'),
    repo_id           TEXT NOT NULL
        REFERENCES swe_gate_repositories (repo_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    commit_sha        TEXT NOT NULL
        CHECK (typeof(commit_sha) = 'text'
               AND length(commit_sha) = 40
               AND commit_sha NOT GLOB '*[^0-9a-f]*'),
    functional_passed INTEGER NOT NULL
        CHECK (typeof(functional_passed) = 'integer'
               AND functional_passed IN (0, 1)),
    gate_verdict      TEXT NOT NULL
        CHECK (gate_verdict IN ('ALLOW_MERGE', 'REJECT_ARCHITECTURAL_VIOLATION')),
    violations_count  INTEGER NOT NULL
        CHECK (typeof(violations_count) = 'integer'
               AND violations_count BETWEEN 0 AND 256),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (typeof(created_at) = 'text'
               AND length(created_at) = 24
               AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
               AND created_at >= '2020-01-01T00:00:00.000Z'
               AND created_at <  '2100-01-01T00:00:00.000Z'),
    CHECK ((gate_verdict = 'ALLOW_MERGE'
            AND functional_passed = 1
            AND violations_count = 0)
           OR (gate_verdict = 'REJECT_ARCHITECTURAL_VIOLATION'
               AND (functional_passed = 0 OR violations_count > 0)))
);

CREATE TABLE IF NOT EXISTS swe_gate_violation_findings (
    violation_id   TEXT PRIMARY KEY
        CHECK (typeof(violation_id) = 'text'
               AND length(violation_id) BETWEEN 8 AND 68
               AND violation_id GLOB 'VIO-*'),
    evaluation_id  TEXT NOT NULL
        REFERENCES swe_gate_patch_evaluations (evaluation_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    violation_type TEXT NOT NULL
        CHECK (violation_type IN ('TYPE_IGNORE', 'DISALLOWED_IMPORT',
                                  'CYCLOMATIC_DELTA', 'INVALID_INPUT')),
    symbol_or_file TEXT NOT NULL
        CHECK (typeof(symbol_or_file) = 'text'
               AND length(symbol_or_file) BETWEEN 1 AND 480),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (typeof(created_at) = 'text'
               AND length(created_at) = 24
               AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
               AND created_at >= '2020-01-01T00:00:00.000Z'
               AND created_at <  '2100-01-01T00:00:00.000Z')
);

CREATE INDEX IF NOT EXISTS idx_swe_gate_evaluations_repo_time
    ON swe_gate_patch_evaluations (repo_id, created_at);
CREATE INDEX IF NOT EXISTS idx_swe_gate_evaluations_commit
    ON swe_gate_patch_evaluations (commit_sha);
CREATE INDEX IF NOT EXISTS idx_swe_gate_evaluations_verdict_time
    ON swe_gate_patch_evaluations (gate_verdict, created_at);
CREATE INDEX IF NOT EXISTS idx_swe_gate_violations_evaluation
    ON swe_gate_violation_findings (evaluation_id, violation_type);

-- ----------------------------------------------------------------------------
-- Append-only: UPDATE is never allowed on any ledger table.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_swe_gate_repositories_no_update
BEFORE UPDATE ON swe_gate_repositories
BEGIN
    SELECT RAISE(ABORT, 'swe_gate_repositories is immutable: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_swe_gate_evaluations_no_update
BEFORE UPDATE ON swe_gate_patch_evaluations
BEGIN
    SELECT RAISE(ABORT, 'swe_gate_patch_evaluations is immutable: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_swe_gate_violations_no_update
BEFORE UPDATE ON swe_gate_violation_findings
BEGIN
    SELECT RAISE(ABORT, 'swe_gate_violation_findings is immutable: UPDATE forbidden');
END;

-- ----------------------------------------------------------------------------
-- No direct DELETE of child rows; the cascade from the parent (already removed
-- at that point) is the only permitted removal path.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_swe_gate_evaluations_no_direct_delete
BEFORE DELETE ON swe_gate_patch_evaluations
WHEN EXISTS (SELECT 1 FROM swe_gate_repositories WHERE repo_id = OLD.repo_id)
BEGIN
    SELECT RAISE(ABORT, 'swe_gate_patch_evaluations is append-only: direct DELETE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_swe_gate_violations_no_direct_delete
BEFORE DELETE ON swe_gate_violation_findings
WHEN EXISTS (SELECT 1 FROM swe_gate_patch_evaluations WHERE evaluation_id = OLD.evaluation_id)
BEGIN
    SELECT RAISE(ABORT, 'swe_gate_violation_findings is append-only: direct DELETE forbidden');
END;

-- ----------------------------------------------------------------------------
-- Cap: an evaluation never owns more violation records than violations_count.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_swe_gate_violations_count_cap
BEFORE INSERT ON swe_gate_violation_findings
WHEN (SELECT COUNT(*) FROM swe_gate_violation_findings
      WHERE evaluation_id = NEW.evaluation_id)
     >= COALESCE((SELECT violations_count FROM swe_gate_patch_evaluations
                  WHERE evaluation_id = NEW.evaluation_id), 0)
BEGIN
    SELECT RAISE(ABORT, 'violation records exceed violations_count of the evaluation');
END;
