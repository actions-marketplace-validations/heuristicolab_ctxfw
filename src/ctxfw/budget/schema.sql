-- ============================================================================
-- TOKENCAST BUDGETER :: 3_schema_ddl.sql
-- Signal   : SIG-947678205487bc66
-- Proposal : PROP-947678205487bc66-H1
-- Horizon  : HORIZON_1
-- manifest_hash (CTXFW evaluate_spec_axioms, status VERIFIED, ACI 1.0000):
--   7b7ef06dfc91c02c73bf8117efd362ffecd01cffdb9d0e5a8700be01c874bdae
-- Engine   : SQLite >= 3.37 (WAL). Typing is enforced with CHECK(typeof(..)).
-- Ledger   : append-only. UPDATE is always aborted; direct DELETE of child rows
--            is aborted; rows disappear only through ON DELETE CASCADE from
--            tokencast_session_budgets.
-- Deviation: tokencast_session_budgets carries an extra max_turns column that
--            the requested column list omitted. It is required by
--            SessionTokenBudgetDTO and by the turn-ordering triggers.
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tokencast_session_budgets (
    session_id        TEXT    PRIMARY KEY
        CHECK (typeof(session_id) = 'text'
               AND length(session_id) BETWEEN 8 AND 68
               AND session_id GLOB 'SES-*'),
    soft_limit_tokens INTEGER NOT NULL
        CHECK (typeof(soft_limit_tokens) = 'integer'
               AND soft_limit_tokens BETWEEN 1 AND 100000000000),
    hard_limit_tokens INTEGER NOT NULL
        CHECK (typeof(hard_limit_tokens) = 'integer'
               AND hard_limit_tokens BETWEEN 1 AND 100000000000),
    max_turns         INTEGER NOT NULL
        CHECK (typeof(max_turns) = 'integer'
               AND max_turns BETWEEN 1 AND 1024),
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (typeof(created_at) = 'text' AND length(created_at) BETWEEN 20 AND 32),
    CHECK (soft_limit_tokens <= hard_limit_tokens)
);

CREATE TABLE IF NOT EXISTS tokencast_turn_telemetry (
    telemetry_id TEXT    PRIMARY KEY
        CHECK (typeof(telemetry_id) = 'text'
               AND length(telemetry_id) BETWEEN 8 AND 68
               AND telemetry_id GLOB 'TEL-*'),
    session_id   TEXT    NOT NULL
        REFERENCES tokencast_session_budgets (session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    turn_index   INTEGER NOT NULL
        CHECK (typeof(turn_index) = 'integer' AND turn_index BETWEEN 0 AND 1023),
    tokens_used  INTEGER NOT NULL
        CHECK (typeof(tokens_used) = 'integer' AND tokens_used BETWEEN 0 AND 20000000),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (typeof(created_at) = 'text' AND length(created_at) BETWEEN 20 AND 32),
    UNIQUE (session_id, turn_index)
);

CREATE TABLE IF NOT EXISTS tokencast_enforcement_events (
    event_id        TEXT    PRIMARY KEY
        CHECK (typeof(event_id) = 'text'
               AND length(event_id) BETWEEN 8 AND 68
               AND event_id GLOB 'EVT-*'),
    session_id      TEXT    NOT NULL
        REFERENCES tokencast_session_budgets (session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    decision        TEXT    NOT NULL
        CHECK (typeof(decision) = 'text'
               AND decision IN ('CONTINUE', 'FORCE_D3_PRUNING', 'EMERGENCY_HALT')),
    forecast_tokens INTEGER NOT NULL
        CHECK (typeof(forecast_tokens) = 'integer'
               AND forecast_tokens BETWEEN 0 AND 100000000000),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (typeof(created_at) = 'text' AND length(created_at) BETWEEN 20 AND 32)
);

CREATE INDEX IF NOT EXISTS idx_tokencast_telemetry_session_turn
    ON tokencast_turn_telemetry (session_id, turn_index);
CREATE INDEX IF NOT EXISTS idx_tokencast_events_session_decision_time
    ON tokencast_enforcement_events (session_id, decision, created_at);
CREATE INDEX IF NOT EXISTS idx_tokencast_events_decision_time
    ON tokencast_enforcement_events (decision, created_at);

-- ----------------------------------------------------------------------------
-- Append-only: UPDATE is never allowed on any ledger table.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tokencast_budgets_no_update
BEFORE UPDATE ON tokencast_session_budgets
BEGIN
    SELECT RAISE(ABORT, 'tokencast_session_budgets is immutable: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_tokencast_telemetry_no_update
BEFORE UPDATE ON tokencast_turn_telemetry
BEGIN
    SELECT RAISE(ABORT, 'tokencast_turn_telemetry is immutable: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_tokencast_events_no_update
BEFORE UPDATE ON tokencast_enforcement_events
BEGIN
    SELECT RAISE(ABORT, 'tokencast_enforcement_events is immutable: UPDATE forbidden');
END;

-- ----------------------------------------------------------------------------
-- No direct DELETE of child rows; the cascade from the budget (parent already
-- removed at that point) is the only permitted removal path.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tokencast_telemetry_no_direct_delete
BEFORE DELETE ON tokencast_turn_telemetry
WHEN EXISTS (SELECT 1 FROM tokencast_session_budgets WHERE session_id = OLD.session_id)
BEGIN
    SELECT RAISE(ABORT, 'tokencast_turn_telemetry is append-only: direct DELETE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_tokencast_events_no_direct_delete
BEFORE DELETE ON tokencast_enforcement_events
WHEN EXISTS (SELECT 1 FROM tokencast_session_budgets WHERE session_id = OLD.session_id)
BEGIN
    SELECT RAISE(ABORT, 'tokencast_enforcement_events is append-only: direct DELETE forbidden');
END;

-- ----------------------------------------------------------------------------
-- Telemetry ordering: turn_index must equal the number of rows already stored
-- for the session (0,1,2,...) and must stay below the session max_turns.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tokencast_telemetry_sequential
BEFORE INSERT ON tokencast_turn_telemetry
WHEN NEW.turn_index <> (SELECT COUNT(*) FROM tokencast_turn_telemetry
                        WHERE session_id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'turn_index must be contiguous starting at 0');
END;

CREATE TRIGGER IF NOT EXISTS trg_tokencast_telemetry_max_turns
BEFORE INSERT ON tokencast_turn_telemetry
WHEN NEW.turn_index >= (SELECT max_turns FROM tokencast_session_budgets
                        WHERE session_id = NEW.session_id)
BEGIN
    SELECT RAISE(ABORT, 'turn_index exceeds session max_turns');
END;

-- ----------------------------------------------------------------------------
-- EMERGENCY_HALT latch: once recorded, the session accepts no more telemetry
-- and no event other than another EMERGENCY_HALT.
-- ----------------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_tokencast_telemetry_halt_latch
BEFORE INSERT ON tokencast_turn_telemetry
WHEN EXISTS (SELECT 1 FROM tokencast_enforcement_events
             WHERE session_id = NEW.session_id AND decision = 'EMERGENCY_HALT')
BEGIN
    SELECT RAISE(ABORT, 'session halted: telemetry rejected after EMERGENCY_HALT');
END;

CREATE TRIGGER IF NOT EXISTS trg_tokencast_events_halt_latch
BEFORE INSERT ON tokencast_enforcement_events
WHEN NEW.decision <> 'EMERGENCY_HALT'
 AND EXISTS (SELECT 1 FROM tokencast_enforcement_events
             WHERE session_id = NEW.session_id AND decision = 'EMERGENCY_HALT')
BEGIN
    SELECT RAISE(ABORT, 'session halted: only EMERGENCY_HALT may follow EMERGENCY_HALT');
END;
