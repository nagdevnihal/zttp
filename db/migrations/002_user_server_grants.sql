-- db/migrations/002_user_server_grants.sql

CREATE TABLE IF NOT EXISTS user_server_grants (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, server_id)
);
