-- Kali NetWatch schema v1.
-- All timestamps are ISO-8601 UTC strings (YYYY-MM-DDTHH:MM:SSZ).

CREATE TABLE networks (
    id          INTEGER PRIMARY KEY,
    cidr        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    is_local    INTEGER NOT NULL DEFAULT 0,   -- directly attached to this Pi (MAC addresses usable)
    created_at  TEXT NOT NULL
);

CREATE TABLE devices (
    id              INTEGER PRIMARY KEY,
    mac             TEXT UNIQUE,              -- normalised aa:bb:cc:dd:ee:ff; NULL when unknown
    mac_randomized  INTEGER NOT NULL DEFAULT 0,
    hostname        TEXT NOT NULL DEFAULT '',
    vendor          TEXT NOT NULL DEFAULT '',
    device_type     TEXT NOT NULL DEFAULT 'unknown',
    device_type_source TEXT NOT NULL DEFAULT 'auto',  -- 'auto' or 'user'
    network_id      INTEGER REFERENCES networks(id),
    current_ip      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('online','offline','unknown')),
    missing_scans   INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT,
    trusted         INTEGER NOT NULL DEFAULT 0,
    custom_name     TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    risk_score      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_devices_network ON devices(network_id);
CREATE INDEX idx_devices_status ON devices(status);

-- Identity (devices) and address observations are kept separate.
CREATE TABLE device_addresses (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    network_id  INTEGER REFERENCES networks(id),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (device_id, ip)
);
CREATE INDEX idx_addresses_ip ON device_addresses(ip);

CREATE TABLE scan_jobs (
    id              INTEGER PRIMARY KEY,
    profile         TEXT NOT NULL CHECK (profile IN ('quick','standard','detailed','custom')),
    trigger         TEXT NOT NULL CHECK (trigger IN ('manual','schedule')),
    requested_by    TEXT NOT NULL DEFAULT '',
    params          TEXT NOT NULL DEFAULT '{}',   -- JSON: networks, targets, ports, timing
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','completed','partial','failed','cancelled','timeout')),
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    progress        TEXT NOT NULL DEFAULT '',     -- human-readable phase, e.g. "network 2/2"
    hosts_up        INTEGER NOT NULL DEFAULT 0,
    hosts_total     INTEGER NOT NULL DEFAULT 0,
    nmap_args       TEXT NOT NULL DEFAULT '',
    log             TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    duration_seconds REAL
);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status, created_at);

CREATE TABLE scan_job_networks (
    job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    network_id  INTEGER REFERENCES networks(id),
    cidr        TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('ok','failed','cancelled','timeout','skipped')),
    error       TEXT NOT NULL DEFAULT '',
    hosts_up    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id, cidr)
);

CREATE TABLE scan_results (
    id          INTEGER PRIMARY KEY,
    job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    ip          TEXT NOT NULL,
    mac         TEXT,
    hostname    TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    ports_scanned INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL
);
CREATE INDEX idx_scan_results_job ON scan_results(job_id);

-- Per-scan presence history used for availability charts.
CREATE TABLE device_observations (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    job_id      INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
    ip          TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN ('online','absent')),
    observed_at TEXT NOT NULL
);
CREATE INDEX idx_device_obs ON device_observations(device_id, observed_at);
CREATE INDEX idx_device_obs_time ON device_observations(observed_at);

CREATE TABLE open_ports (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL CHECK (state IN ('open','closed')),
    service     TEXT NOT NULL DEFAULT '',
    product     TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    extrainfo   TEXT NOT NULL DEFAULT '',
    script_output TEXT NOT NULL DEFAULT '',   -- only populated when non-intrusive NSE output exists
    scope       TEXT NOT NULL DEFAULT 'top' CHECK (scope IN ('top','explicit')), -- how the port was discovered
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    closed_at   TEXT,
    UNIQUE (device_id, port, protocol)
);
CREATE INDEX idx_open_ports_state ON open_ports(state);

CREATE TABLE service_observations (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    job_id      INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    service     TEXT NOT NULL DEFAULT '',
    product     TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX idx_service_obs ON service_observations(device_id, port, observed_at);

CREATE TABLE security_findings (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_key        TEXT NOT NULL,
    port            INTEGER NOT NULL DEFAULT 0,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    weight          INTEGER NOT NULL DEFAULT 0,
    service         TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','acknowledged')),
    first_detected  TEXT NOT NULL,
    last_detected   TEXT NOT NULL,
    resolved_at     TEXT,
    UNIQUE (device_id, rule_key, port)
);
CREATE INDEX idx_findings_status ON security_findings(status, severity);

CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','low','medium','high','critical')),
    device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    job_id      INTEGER REFERENCES scan_jobs(id) ON DELETE SET NULL,
    title       TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_time ON events(created_at);
CREATE INDEX idx_events_type ON events(type, created_at);

CREATE TABLE alert_rules (
    event_type       TEXT PRIMARY KEY,
    enabled          INTEGER NOT NULL DEFAULT 1,
    min_severity     TEXT NOT NULL DEFAULT 'medium' CHECK (min_severity IN ('info','low','medium','high','critical')),
    cooldown_seconds INTEGER NOT NULL DEFAULT 900
);

CREATE TABLE notification_history (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    channel     TEXT NOT NULL DEFAULT 'telegram',
    event_type  TEXT NOT NULL,
    dedupe_key  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN ('sent','failed','suppressed','skipped')),
    message     TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_notif_dedupe ON notification_history(dedupe_key, created_at);

CREATE TABLE app_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin','viewer')),
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE sessions (
    token_hash  TEXT PRIMARY KEY,           -- SHA-256 of the cookie value; raw token never stored
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    client_ip   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    client_ip   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_time ON audit_log(created_at);
