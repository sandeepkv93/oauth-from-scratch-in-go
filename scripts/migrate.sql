-- OAuth Server Database Migration Script
-- Version: 1.0.0
-- Description: Initial schema creation for OAuth 2.0 server

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schema version tracking table
CREATE TABLE IF NOT EXISTS schema_versions (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMP DEFAULT NOW(),
    applied_by TEXT DEFAULT current_user
);

-- Insert initial version if not exists
INSERT INTO schema_versions (version, description) 
SELECT 1, 'Initial OAuth 2.0 schema creation'
WHERE NOT EXISTS (SELECT 1 FROM schema_versions WHERE version = 1);

-- Users table for OAuth resource owners
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- OAuth clients table
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{}',
    response_types TEXT[] DEFAULT '{"code"}',
    is_public BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Scopes definition table
CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Authorization codes table
CREATE TABLE IF NOT EXISTS authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri VARCHAR(512) NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    nonce VARCHAR(255),
    state VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Access tokens table
CREATE TABLE IF NOT EXISTS access_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token TEXT UNIQUE NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revoked_by UUID REFERENCES users(id),
    revocation_reason TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token VARCHAR(255) UNIQUE NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    access_token_id UUID NOT NULL REFERENCES access_tokens(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Audit log for security events
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id),
    client_id VARCHAR(255) REFERENCES clients(client_id),
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    severity VARCHAR(20) DEFAULT 'info',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Client sessions for tracking active sessions
CREATE TABLE IF NOT EXISTS client_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    ip_address INET,
    user_agent TEXT,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);
CREATE INDEX IF NOT EXISTS idx_clients_active ON clients(is_active) WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON authorization_codes(code);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user ON authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_unused ON authorization_codes(used) WHERE used = FALSE;

CREATE INDEX IF NOT EXISTS idx_access_tokens_token_hash ON access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_active ON access_tokens(revoked) WHERE revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active ON refresh_tokens(revoked) WHERE revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_client ON audit_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON client_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON client_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_client ON client_sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON client_sessions(expires_at);

-- Cleanup functions for expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    -- Mark expired access tokens as revoked
    UPDATE access_tokens 
    SET revoked = TRUE, revoked_at = NOW(), revocation_reason = 'expired'
    WHERE expires_at < NOW() AND revoked = FALSE;
    
    -- Mark expired refresh tokens as revoked
    UPDATE refresh_tokens 
    SET revoked = TRUE, revoked_at = NOW()
    WHERE expires_at < NOW() AND revoked = FALSE;
    
    -- Delete expired authorization codes
    DELETE FROM authorization_codes 
    WHERE expires_at < NOW() - INTERVAL '1 day';
    
    -- Delete expired sessions
    DELETE FROM client_sessions 
    WHERE expires_at < NOW();
    
    -- Clean up old audit logs (older than 90 days)
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Trigger function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clients_updated_at 
    BEFORE UPDATE ON clients 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Security policies (Row Level Security)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Insert default scopes
INSERT INTO scopes (name, description, is_default) VALUES
('openid', 'OpenID Connect scope for authentication', true),
('profile', 'Access to user profile information', true),
('email', 'Access to user email address', true),
('read', 'Read access to resources', false),
('write', 'Write access to resources', false),
('admin', 'Administrative access to all resources', false)
ON CONFLICT (name) DO NOTHING;

-- Create database roles for different access levels
DO $$
BEGIN
    -- Application role with limited permissions
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'oauth_app') THEN
        CREATE ROLE oauth_app;
        GRANT CONNECT ON DATABASE CURRENT_DATABASE() TO oauth_app;
        GRANT USAGE ON SCHEMA public TO oauth_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO oauth_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO oauth_app;
    END IF;
    
    -- Read-only role for monitoring
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'oauth_readonly') THEN
        CREATE ROLE oauth_readonly;
        GRANT CONNECT ON DATABASE CURRENT_DATABASE() TO oauth_readonly;
        GRANT USAGE ON SCHEMA public TO oauth_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO oauth_readonly;
    END IF;
END $$;

-- Grant permissions to application user
GRANT oauth_app TO oauth_service;

-- Schedule cleanup job (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-expired-tokens', '0 */6 * * *', 'SELECT cleanup_expired_tokens();');

COMMIT;