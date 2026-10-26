-- NHI security prototype: PostgreSQL schema + seed data
-- Credential values are NEVER stored here: secret_ref points to the credential store.

CREATE TABLE identities (
    id          TEXT PRIMARY KEY,
    purpose     TEXT NOT NULL,
    owner       TEXT,                       -- nullable on purpose (to seed the NO_OWNER risk)
    status      TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    id                SERIAL PRIMARY KEY,
    identity_id       TEXT NOT NULL REFERENCES identities(id),
    tool              TEXT NOT NULL,        -- documents | database | tickets | '*'
    action            TEXT NOT NULL,        -- read | query | create | '*'
    resource_pattern  TEXT NOT NULL         -- e.g. 'deployments', 'docs/public/*', '*'
);

CREATE TABLE credentials (
    id           SERIAL PRIMARY KEY,
    identity_id  TEXT NOT NULL REFERENCES identities(id),
    type         TEXT NOT NULL,             -- api_key | jwt | certificate
    secret_ref   TEXT NOT NULL,             -- reference to the store (e.g. vault://...), not the secret
    issued_at    TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);

CREATE TABLE audit_events (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id   TEXT NOT NULL,
    identity_id  TEXT,                      -- null if the caller could not be identified
    tool         TEXT NOT NULL,
    action       TEXT NOT NULL,
    resource     TEXT NOT NULL,
    decision     TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    reason_code  TEXT NOT NULL
);

CREATE TABLE risk_findings (
    id           SERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    identity_id  TEXT REFERENCES identities(id),
    risk_type    TEXT NOT NULL,             -- EXPIRED_BUT_ACTIVE | NO_OWNER | WILDCARD_PERMISSION | SHARED_CREDENTIAL | SECRET_IN_REPO
    severity     TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    details      TEXT
);

CREATE INDEX idx_audit_identity_ts ON audit_events (identity_id, ts);
CREATE INDEX idx_credentials_identity ON credentials (identity_id);

-- ---------------------------------------------------------------- seed data

INSERT INTO identities (id, purpose, owner, status) VALUES
    ('agent-deploy-reader', 'Summarize deployment status', 'alice', 'active'),
    ('agent-ticket-writer', 'Open tickets',                'bob',   'active'),
    ('agent-legacy-admin',  'Old test agent',              NULL,    'active'),
    ('agent-reporting',     'Reporting',                   'carol', 'active');

INSERT INTO permissions (identity_id, tool, action, resource_pattern) VALUES
    ('agent-deploy-reader', 'database',  'query',  'deployments'),
    ('agent-deploy-reader', 'documents', 'read',   'docs/public/*'),
    ('agent-ticket-writer', 'tickets',   'create', 'OPS'),
    ('agent-legacy-admin',  '*',         '*',      '*'),
    ('agent-reporting',     'database',  'query',  'deployments');

INSERT INTO credentials (identity_id, type, secret_ref, issued_at, expires_at, revoked_at) VALUES
    ('agent-deploy-reader', 'api_key', 'vault://demo/deploy-reader', now(),                       now() + interval '24 hours', NULL),
    -- seeded risk: the same secret_ref is used by two identities
    ('agent-ticket-writer', 'api_key', 'vault://demo/shared-key-01', now(),                       now() + interval '24 hours', NULL),
    ('agent-reporting',     'api_key', 'vault://demo/shared-key-01', now(),                       now() + interval '24 hours', NULL),
    -- seeded risk: expired credential on an identity still marked active
    ('agent-legacy-admin',  'api_key', 'vault://demo/legacy-admin',  now() - interval '90 days',  now() - interval '30 days',  NULL);
