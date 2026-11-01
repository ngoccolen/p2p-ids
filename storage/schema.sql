PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS peers (
    peer_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    p2p_port INTEGER NOT NULL,
    api_port INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_seen REAL NOT NULL,
    rtt_ms REAL
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    fwd_packets INTEGER,
    bwd_packets INTEGER,
    syn INTEGER,
    ack INTEGER,
    fin INTEGER,
    rst INTEGER,
    psh INTEGER,
    urg INTEGER,
    anomaly_score REAL DEFAULT 0.0,
    is_anomaly INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    origin_peer TEXT NOT NULL,
    lamport INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    score REAL,
    description TEXT,
    evidence TEXT,
    status TEXT DEFAULT 'NEW',
    is_local INTEGER DEFAULT 1,
    received_from TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(start_ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
