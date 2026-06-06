-- db/migrations/003_policies.sql
-- Table 3: RBAC Ruleset
-- One row per role. allowed_environments is a PostgreSQL array — the RBAC
-- engine checks: does server.environment = ANY(policy.allowed_environments)?

CREATE TABLE IF NOT EXISTS policies (
    id                   UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    role                 VARCHAR(50)   NOT NULL UNIQUE,
    allowed_environments VARCHAR(50)[] NOT NULL,
    allowed_commands     TEXT[]        NULL
);

CREATE INDEX IF NOT EXISTS idx_policies_role ON policies(role);

COMMENT ON TABLE  policies IS 'RBAC ruleset — maps roles to allowed environments and optional command whitelists';
COMMENT ON COLUMN policies.allowed_environments IS 'Array of environment tags this role can access e.g. {dev,staging}';
COMMENT ON COLUMN policies.allowed_commands     IS 'Optional command whitelist. NULL = full shell. Multiplexers always blocked regardless.';
