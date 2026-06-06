-- db/migrations/001_users.sql
-- Table 1: Identity & Authentication
-- UUIDs as PKs prevent sequential ID enumeration attacks.
-- bcrypt/Argon2id hash stored — plaintext structurally prohibited.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(50)  UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(50)  NOT NULL,
    failed_attempts INT          NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP    NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username     ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;

COMMENT ON TABLE  users IS 'ZTTP identity store — every engineering login identity';
COMMENT ON COLUMN users.password_hash IS 'bcrypt ($2a$12$...) or Argon2id — NEVER store plaintext';
COMMENT ON COLUMN users.locked_until  IS 'Populated after 5 failed attempts; cleared on successful login';
