-- Idempotent seed — runs on every `dev` startup; safe to run multiple times.
-- Admin user: admin@admin.com / 12345678 (bcrypt hash for "12345678", rounds=10)
-- Matches NodeAdmin seed exactly.

INSERT OR IGNORE INTO settings (id, initial, name, description, theme, fe_template, created_by, updated_by)
VALUES (
    'setting-singleton-id-0000000001',
    'CA',
    'CppAdmin',
    'A C++ Drogon bootstrap admin panel',
    'Blue',
    'agency-consulting-002-creative-agency',
    'system',
    'system'
);

INSERT OR IGNORE INTO roles (id, name, status, created_by, updated_by)
VALUES
    ('role-administrator-000000000001', 'Administrator', 'Active', 'system', 'system'),
    ('role-user-000000000000000000002', 'User',          'Active', 'system', 'system');

-- bcrypt hash of "12345678" with rounds=10
-- $2b$10$... (pre-computed; if you change BCRYPT_ROUNDS regenerate this hash)
INSERT OR IGNORE INTO users (id, code, name, phone, email, password, status, timezone, created_by, updated_by)
VALUES (
    'user-admin-00000000000000000001',
    'ADM001',
    'Administrator',
    '000000000000',
    'admin@admin.com',
    '$2b$10$EixZaYVK1fsbw1ZfbX3OXexnF3ooU3EEbaqTnEkMnXiH05NPdcnFG',
    'Active',
    'UTC',
    'system',
    'system'
);

INSERT OR IGNORE INTO users_roles (user_id, role_id)
VALUES ('user-admin-00000000000000000001', 'role-administrator-000000000001');
