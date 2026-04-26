CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

INSERT INTO permissions (name, description) VALUES
    ('users.read', 'View users'),
    ('users.write', 'Create and update users'),
    ('users.delete', 'Delete users'),
    ('roles.manage', 'Manage roles and permissions'),
    ('tenant:create', 'Create tenants'),
    ('tenant:manage', 'Manage tenant roles and members'),
    ('tenant:invite', 'Invite users to tenants'),
    ('tenant:members:read', 'View tenant members')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'super_admin' AND p.name IN ('users.read', 'users.write', 'users.delete', 'roles.manage', 'tenant:create', 'tenant:manage', 'tenant:invite', 'tenant:members:read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'admin' AND p.name IN ('users.read', 'users.write', 'tenant:create', 'tenant:manage', 'tenant:invite', 'tenant:members:read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'tenant_admin' AND p.name IN ('users.read', 'users.write', 'tenant:manage', 'tenant:invite', 'tenant:members:read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'tenant_member' AND p.name IN ('users.read', 'tenant:members:read')
ON CONFLICT DO NOTHING;
