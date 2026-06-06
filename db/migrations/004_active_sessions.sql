-- db/migrations/004_active_sessions.sql
-- Table 4: Real-Time Session State & Kill Switch Anchor
-- The most dynamic table — high read/write throughput during normal operation.
-- proxy_node_ip is critical: it tells the Kill Switch exactly which ZTTP node
-- holds the active TCP socket so the gRPC signal can be routed correctly.

CREATE TABLE IF NOT EXISTS active_sessions (
    session_id    UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    server_id     UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    proxy_node_ip INET        NOT NULL,
    start_time    TIMESTAMP   NOT NULL DEFAULT NOW(),
    status        VARCHAR(30) NOT NULL DEFAULT 'active'
        CHECK (status IN (
            'active',
            'terminated',
            'terminated-timeout',
            'terminated-kill'
        ))
);

CREATE INDEX IF NOT EXISTS idx_active_sessions_user_id    ON active_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_active_sessions_status     ON active_sessions(status)       WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_active_sessions_proxy_node ON active_sessions(proxy_node_ip) WHERE status = 'active';

COMMENT ON TABLE  active_sessions IS 'Live session registry — bridges authenticated user to active TCP socket';
COMMENT ON COLUMN active_sessions.session_id    IS 'Kill Switch targeting key — UUID generated at PTY inception';
COMMENT ON COLUMN active_sessions.proxy_node_ip IS 'Which ZTTP container holds this sessions TCP socket — for gRPC kill routing';
COMMENT ON COLUMN active_sessions.status        IS 'active | terminated | terminated-timeout | terminated-kill';
