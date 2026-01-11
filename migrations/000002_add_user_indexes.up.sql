-- Add additional indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at);

-- Add composite index for common queries
CREATE INDEX IF NOT EXISTS idx_users_email_is_active ON users(email, is_active);