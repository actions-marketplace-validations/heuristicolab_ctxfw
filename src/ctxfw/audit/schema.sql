-- ============================================================================
-- TRACEKIT HASH LEDGER :: 3_schema_ddl.sql
-- Signal   : SIG-728856af9bd65ae0
-- Proposal : PROP-728856af9bd65ae0-H1
-- Horizon  : HORIZON_1
-- manifest_hash (CTXFW evaluate_spec_axioms, status VERIFIED, ACI 1.0000):
--   7fe956c6456ad27a1f570080151730b426b09b4026b33c5269830925296a824c
-- Engine   : SQLite >= 3.37 (WAL). Typing is enforced with CHECK(typeof(..)).
-- Ledger   : append-only. UPDATE is always aborted; direct DELETE of child rows
--            is aborted; rows disappear only through ON DELETE CASCADE from
--            tracekit_sessions.
-- Scope    : SQLite cannot compute SHA-256, so the engine enforces format,
--            contiguity, linkage (prev_block_hash = predecessor current hash or
--            genesis), timestamp monotonicity and the tamper latch. Recomputing
--            current_block_hash is the job of the backward audit (see
--            specs/4_pytest_tdd_matrix.py :: ReferenceVerifier).
-- Timestamps are canonical UTC text YYYY-MM-DDTHH:MM:SS.ffffffZ (27 chars) and
-- are supplied by the caller; the schema has no wall-clock DEFAULT.
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tracekit_sessions (
    session_id   TEXT PRIMARY KEY
        CHECK (typeof(session_id) = 'text'
               AND length(session_id) BETWEEN 8 AND 68
               AND session_id GLOB 'SES-*'),
    genesis_hash TEXT NOT NULL
        CHECK (typeof(genesis_hash) = 'text'
               AND length(genesis_hash) = 64
               AND genesis_hash NOT GLOB '*[^0-9a-f]*'),
    created_at   TEXT NOT NULL
        CHECK (typeof(created_at) = 'text'
               AND length(created_at) = 27
               AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
               AND created_at >= '2020-01-01T00:00:00.000000Z'
               AND created_at <  '2100-01-01T00:00:00.000000Z')
);

CREATE TABLE IF NOT EXISTS tracekit_audit_blocks (
    block_id           TEXT PRIMARY KEY
        CHECK (typeof(block_id) = 'text'
               AND length(block_id) BETWEEN 8 AND 68
               AND block_id GLOB 'BLK-*'),
    session_id         TEXT NOT NULL
        REFERENCES tracekit_sessions (session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    block_seq          INTEGER NOT NULL
        CHECK (typeof(block_seq) = 'integer' AND block_seq BETWEEN 0 AND 1000000),
    prev_block_hash    TEXT NOT NULL
        CHECK (typeof(prev_block_hash) = 'text'
               AND length(prev_block_hash) = 64
               AND prev_block_hash NOT GLOB '*[^0-9a-f]*'),
    current_block_hash TEXT NOT NULL
        CHECK (typeof(current_block_hash) = 'text'
               AND length(current_block_hash) = 64
               AND current_block_hash NOT GLOB '*[^0-9a-f]*'),
    intent_digest      TEXT NOT NULL
        CHECK (typeof(intent_digest) = 'text'
               AND length(intent_digest) = 64
               AND intent_digest NOT GLOB '*[^0-9a-f]*'),
    reasoning_digest   TEXT NOT NULL
        CHECK (typeof(reasoning_digest) = 'text'
               AND length(reasoning_digest) = 64
               AND reasoning_digest NOT GLOB '*[^0-9a-f]*'),
    action_digest      TEXT NOT NULL
        CHECK (typeof(action_digest) = 'text'
               AND length(action_digest) = 64
               AND action_digest NOT GLOB '*[^0-9a-f]*'),
    created_at         TEXT NOT NULL
        CHECK (typeof(created_at) = 'text'
               AND length(created_at) = 27
               AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
               AND created_at >= '2020-01-01T00:00:00.000000Z'
               AND created_at <  '2100-01-01T00:00:00.000000Z'),
    UNIQUE (session_id, block_seq)
);

CREATE TABLE IF NOT EXISTS tracekit_verification_events (
    event_id    TEXT PRIMARY KEY
        CHECK (typeof(event_id) = 'text'
               AND length(event_id) BETWEEN 8 AND 68
               AND event_id GLOB 'EVT-*'),
    session_id  TEXT NOT NULL
        REFERENCES tracekit_sessions (session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    is_tampered INTEGER NOT NULL
        CHECK (is_tampered IN (0, 1)),
    broken_seq  INTEGER,
    created_at  TEXT NOT NULL
        CHECK (typeof(created_at) = 'text'
               AND length(created_at) = 27
               AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
               AND created_at >= '2020-01-01T00:00:00.000000Z'
               AND created_at <  '2100-01-01T00:00:00.000000Z'),
    CHECK ((is_tampered = 1
            AND typeof(broken_seq) = 'integer'
            AND broken_seq BETWEEN 0 AND 1000000)
           OR (is_tampered = 0 AND broken_seq IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_tracekit_blocks_session_time
    ON tracekit_audit_blocks (session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tracekit_blocks_current_hash
    ON tracekit_audit_blocks (current_block_hash);
CREATE INDEX IF NOT EXISTS idx_tracekit_events_session_time
    ON tracekit_verification_events (session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tracekit_events_tampered_time
    ON tracekit_verification_events (is_tampered, created_at);

-- ----------------------------------------------------------------------------
-- Append-only: UPDATE is never allowed on any ledger table.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tracekit_sessions_no_update
BEFORE UPDATE ON tracekit_sessions
BEGIN
    SELECT RAISE(ABORT, 'tracekit_sessions is immutable: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_no_update
BEFORE UPDATE ON tracekit_audit_blocks
BEGIN
    SELECT RAISE(ABORT, 'tracekit_audit_blocks is immutable: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_tracekit_events_no_update
BEFORE UPDATE ON tracekit_verification_events
BEGIN
    SELECT RAISE(ABORT, 'tracekit_verification_events is immutable: UPDATE forbidden');
END;

-- ----------------------------------------------------------------------------
-- No direct DELETE of child rows; the cascade from the session (parent already
-- removed at that point) is the only permitted removal path.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_no_direct_delete
BEFORE DELETE ON tracekit_audit_blocks
WHEN EXISTS (SELECT 1 FROM tracekit_sessions WHERE session_id = OLD.session_id)
BEGIN
    SELECT RAISE(ABORT, 'tracekit_audit_blocks is append-only: direct DELETE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_tracekit_events_no_direct_delete
BEFORE DELETE ON tracekit_verification_events
WHEN EXISTS (SELECT 1 FROM tracekit_sessions WHERE session_id = OLD.session_id)
BEGIN
    SELECT RAISE(ABORT, 'tracekit_verification_events is append-only: direct DELETE forbidden');
END;

-- ----------------------------------------------------------------------------
-- Block ordering: block_seq must equal the number of rows already stored for
-- the session (0, 1, 2, ...), preventing gaps, duplicates and reordering.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_sequential
BEFORE INSERT ON tracekit_audit_blocks
WHEN NEW.block_seq <> (SELECT COUNT(*) FROM tracekit_audit_blocks
                       WHERE session_id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'block_seq must be contiguous starting at 0');
END;

-- ----------------------------------------------------------------------------
-- Chain linkage: prev_block_hash must equal the predecessor current_block_hash,
-- or the session genesis_hash for block_seq = 0.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_chain_link
BEFORE INSERT ON tracekit_audit_blocks
WHEN NEW.prev_block_hash <> COALESCE(
        (SELECT current_block_hash FROM tracekit_audit_blocks
         WHERE session_id = NEW.session_id AND block_seq = NEW.block_seq - 1),
        (SELECT genesis_hash FROM tracekit_sessions
         WHERE session_id = NEW.session_id))
BEGIN
    SELECT RAISE(ABORT, 'prev_block_hash does not match the predecessor hash');
END;

-- ----------------------------------------------------------------------------
-- Timestamps never decrease along the chain (session -> block 0 -> block 1 ...).
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_timestamp_monotonic
BEFORE INSERT ON tracekit_audit_blocks
WHEN EXISTS (SELECT 1 FROM tracekit_audit_blocks
             WHERE session_id = NEW.session_id
               AND block_seq = NEW.block_seq - 1
               AND created_at > NEW.created_at)
BEGIN
    SELECT RAISE(ABORT, 'block timestamp must not decrease');
END;

CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_after_session
BEFORE INSERT ON tracekit_audit_blocks
WHEN NEW.block_seq = 0
 AND NEW.created_at < (SELECT created_at FROM tracekit_sessions
                       WHERE session_id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'first block must not predate its session');
END;

-- ----------------------------------------------------------------------------
-- Tamper latch: once a tampered verdict is recorded, the session accepts no new
-- block and no clean verdict (the tampered verdict is sticky).
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tracekit_blocks_tamper_latch
BEFORE INSERT ON tracekit_audit_blocks
WHEN EXISTS (SELECT 1 FROM tracekit_verification_events
             WHERE session_id = NEW.session_id AND is_tampered = 1)
BEGIN
    SELECT RAISE(ABORT, 'session tampered: new blocks rejected');
END;

CREATE TRIGGER IF NOT EXISTS trg_tracekit_events_tamper_sticky
BEFORE INSERT ON tracekit_verification_events
WHEN NEW.is_tampered = 0
 AND EXISTS (SELECT 1 FROM tracekit_verification_events
             WHERE session_id = NEW.session_id AND is_tampered = 1)
BEGIN
    SELECT RAISE(ABORT, 'session tampered: a clean verdict cannot overwrite a tampered verdict');
END;

CREATE TRIGGER IF NOT EXISTS trg_tracekit_events_broken_seq_in_range
BEFORE INSERT ON tracekit_verification_events
WHEN NEW.is_tampered = 1
 AND NEW.broken_seq >= (SELECT COUNT(*) FROM tracekit_audit_blocks
                        WHERE session_id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'broken_seq must reference an audited block');
END;
