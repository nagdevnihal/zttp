-- db/seed.sql
-- Development seed data — DO NOT run in production.
-- Passwords are bcrypt hash of "devpassword123" at cost=12.
-- Generate fresh hashes with: go run tools/hashpw/main.go <password>

-- Users
INSERT INTO users (username, password_hash, role) VALUES
    ('jdoe',    '$2a$12$1.3El2Y7Qw7TZSIyeXit.ee7TpzMeUgVyBR4OA5kOuGjt6TPy1ui.', 'sre-tier1'),
    ('alice',   '$2a$12$1.3El2Y7Qw7TZSIyeXit.ee7TpzMeUgVyBR4OA5kOuGjt6TPy1ui.', 'backend-dev'),
    ('bob',     '$2a$12$1.3El2Y7Qw7TZSIyeXit.ee7TpzMeUgVyBR4OA5kOuGjt6TPy1ui.', 'backend-dev'),
    ('auditor', '$2a$12$1.3El2Y7Qw7TZSIyeXit.ee7TpzMeUgVyBR4OA5kOuGjt6TPy1ui.', 'auditor'),
    ('admin',   '$2a$12$fN7BkRyNmDdHB7PAO5pA1O6BFAIM2UI.BBZ9GXJsRvlrsWTrt6G92', 'superadmin')
ON CONFLICT (username) DO NOTHING;

-- Servers (vault paths match what vault-seed.sh populates)
INSERT INTO servers (hostname, private_ip, vault_secret_path, environment) VALUES
    ('dev-app-01',   '10.0.1.10', 'secret/data/ssh/dev-app-01',   'dev'),
    ('dev-db-01',    '10.0.1.11', 'secret/data/ssh/dev-db-01',    'dev'),
    ('stage-web-01', '10.0.2.10', 'secret/data/ssh/stage-web-01', 'staging'),
    ('stage-db-01',  '10.0.2.11', 'secret/data/ssh/stage-db-01',  'staging'),
    ('prod-app-01',  '10.0.3.10', 'secret/data/ssh/prod-app-01',  'production'),
    ('prod-db-01',   '10.0.3.11', 'secret/data/ssh/prod-db-01',   'production')
ON CONFLICT (hostname) DO NOTHING;

-- RBAC Policies
INSERT INTO policies (role, allowed_environments, allowed_commands) VALUES
    ('sre-tier1',   ARRAY['dev','staging','production'], NULL),
    ('superadmin',  ARRAY['dev','staging','production'], NULL),
    ('backend-dev', ARRAY['dev','staging'],              NULL),
    ('auditor',     ARRAY['dev'],                        ARRAY['ls','cat','grep','tail','head','wc','journalctl','systemctl status'])
ON CONFLICT (role) DO NOTHING;
