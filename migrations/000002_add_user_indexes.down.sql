-- Remove additional indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_users_email_is_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_updated_at;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_created_at;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_is_active;
DROP INDEX CONCURRENTLY IF EXISTS idx_users_role;