-- Existing CSAI progress migration plus authentication ownership migration.
-- Back up the database before running. Run once against the target PostgreSQL DB.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS current_stage VARCHAR DEFAULT 'Queued';

UPDATE scans
SET progress = 100, current_stage = COALESCE(current_stage, 'Scan completed')
WHERE status = 'done' AND progress = 0;

UPDATE scans SET current_stage = 'Queued'
WHERE current_stage IS NULL AND status = 'pending';

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id UUID NULL REFERENCES users(id);
CREATE INDEX IF NOT EXISTS ix_scans_user_id ON scans(user_id);

-- Legacy scans remain user_id NULL and are not visible to newly registered users.
