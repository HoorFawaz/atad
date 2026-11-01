-- atad case database schema (one SQLite file per case).
-- All timestamps are ISO-8601 strings in UTC (e.g. 2026-11-07T00:12:00+00:00).

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id            TEXT PRIMARY KEY,                  -- CASE-001
    name          TEXT NOT NULL,
    profile       TEXT NOT NULL CHECK (profile IN ('soc','dfir','full')),
    description   TEXT NOT NULL DEFAULT '',
    simulated     INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0,1)),
    created_at    TEXT NOT NULL,
    atad_version  TEXT NOT NULL
);

-- Authorized network scope for this case.
CREATE TABLE IF NOT EXISTS targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    TEXT NOT NULL REFERENCES cases(id),
    value      TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('ip','cidr','hostname')),
    is_public  INTEGER NOT NULL DEFAULT 0 CHECK (is_public IN (0,1)),
    added_at   TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    UNIQUE (case_id, value)
);

-- Detected tools (atad doctor / start of each run).
CREATE TABLE IF NOT EXISTS tools (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      TEXT NOT NULL REFERENCES cases(id),
    name         TEXT NOT NULL,
    version      TEXT,
    path         TEXT,
    available    INTEGER NOT NULL CHECK (available IN (0,1)),
    reason       TEXT,                               -- why unavailable
    detected_at  TEXT NOT NULL
);

-- Every tool run or collector run.
CREATE TABLE IF NOT EXISTS executions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL REFERENCES cases(id),
    module        TEXT NOT NULL,
    tool          TEXT NOT NULL,
    tool_version  TEXT,
    command       TEXT,                              -- JSON list of arguments
    target        TEXT,
    collection_mode TEXT NOT NULL CHECK (collection_mode IN ('local','import','network')),
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL CHECK (status IN ('success','failed','skipped','unavailable','timeout')),
    exit_code     INTEGER,
    raw_ref       TEXT,                              -- relative path in case folder
    raw_sha256    TEXT,
    stderr_excerpt TEXT,
    error         TEXT,
    elevated      INTEGER CHECK (elevated IN (0,1))  -- ran with admin rights?
);

CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,                -- EVD-000001
    case_id         TEXT NOT NULL REFERENCES cases(id),
    kind            TEXT NOT NULL,
    source_module   TEXT NOT NULL,
    source_tool     TEXT NOT NULL,
    tool_version    TEXT,
    collection_mode TEXT NOT NULL CHECK (collection_mode IN ('local','import','network')),
    host            TEXT NOT NULL,
    host_declared   INTEGER NOT NULL DEFAULT 0 CHECK (host_declared IN (0,1)),
    collected_at    TEXT NOT NULL,
    event_time      TEXT,
    execution_id    INTEGER REFERENCES executions(id),
    raw_ref         TEXT,
    raw_sha256      TEXT,
    summary         TEXT NOT NULL,
    data            TEXT NOT NULL DEFAULT '{}',      -- JSON
    simulated       INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0,1)),
    status          TEXT NOT NULL CHECK (status IN ('collected','partial','error'))
);
CREATE INDEX IF NOT EXISTS ix_evidence_time ON evidence(event_time);
CREATE INDEX IF NOT EXISTS ix_evidence_host ON evidence(host);
CREATE INDEX IF NOT EXISTS ix_evidence_kind ON evidence(kind);

-- Correlation keys extracted from evidence.
CREATE TABLE IF NOT EXISTS observables (
    evidence_id  TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,
    value        TEXT NOT NULL,
    PRIMARY KEY (evidence_id, type, value)
);
CREATE INDEX IF NOT EXISTS ix_observables_lookup ON observables(type, value);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,                    -- FND-0001
    case_id     TEXT NOT NULL REFERENCES cases(id),
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL CHECK (category IN ('observation','suspicious','correlated','hypothesis')),
    severity    TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    confidence  TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    rule_id     TEXT,
    rationale   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id  TEXT NOT NULL REFERENCES evidence(id),
    PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES cases(id),
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,                       -- list file / feed name
    confidence  TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
    description TEXT NOT NULL DEFAULT '',
    added_at    TEXT NOT NULL,
    UNIQUE (case_id, type, value, source)
);
CREATE INDEX IF NOT EXISTS ix_iocs_lookup ON iocs(type, value);

CREATE TABLE IF NOT EXISTS timeline_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      TEXT NOT NULL REFERENCES cases(id),
    event_time   TEXT NOT NULL,
    host         TEXT NOT NULL,
    description  TEXT NOT NULL,
    evidence_id  TEXT REFERENCES evidence(id),
    finding_id   TEXT REFERENCES findings(id)
);
CREATE INDEX IF NOT EXISTS ix_timeline_time ON timeline_events(event_time);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES cases(id),
    format      TEXT NOT NULL CHECK (format IN ('html','json','pdf')),
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
