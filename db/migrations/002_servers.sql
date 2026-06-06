-- db/migrations/002_servers.sql
-- Table 2: Infrastructure Inventory
-- CRITICALLY: this table contains ZERO private key material.
-- Keys live exclusively in HashiCorp Vault, addressed by vault_secret_path.

CREATE TABLE IF NOT EXISTS servers (
    id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname          VARCHAR(100) UNIQUE NOT NULL,
    private_ip        INET         NOT NULL,
    vault_secret_path VARCHAR(255) NOT NULL,
    environment       VARCHAR(50)  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_servers_hostname    ON servers(hostname);
CREATE INDEX IF NOT EXISTS idx_servers_environment ON servers(environment);

COMMENT ON TABLE  servers IS 'Infrastructure inventory — maps hostnames to IPs and Vault key paths';
COMMENT ON COLUMN servers.private_ip        IS 'Proxy connects via IP (not DNS) to prevent TTL race conditions and spoofing';
COMMENT ON COLUMN servers.vault_secret_path IS 'Vault KV path e.g. secret/data/ssh/prod-db-01';
COMMENT ON COLUMN servers.environment       IS 'Classification tag: dev | staging | production | pci-secure';
