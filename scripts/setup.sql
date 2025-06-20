-- OAuth Server Setup Script
-- This script creates sample data for testing the OAuth server

-- Insert default scopes
INSERT INTO scopes (name, description, is_default) VALUES
('openid', 'OpenID Connect scope for authentication', true),
('profile', 'Access to user profile information', true),
('email', 'Access to user email address', true),
('read', 'Read access to resources', false),
('write', 'Write access to resources', false),
('admin', 'Administrative access', false)
ON CONFLICT (name) DO NOTHING;

-- Insert sample users (password is 'password' hashed with bcrypt)
INSERT INTO users (username, email, password, scopes) VALUES
('admin', 'admin@example.com', '$2a$10$X9wdJ7KQsRgKpRpJvLJ5QeGpH8hV7bR0T9vD2nKRqzJQzNv0WwJZ6', ARRAY['openid', 'profile', 'email', 'read', 'write', 'admin']),
('user1', 'user1@example.com', '$2a$10$X9wdJ7KQsRgKpRpJvLJ5QeGpH8hV7bR0T9vD2nKRqzJQzNv0WwJZ6', ARRAY['openid', 'profile', 'email', 'read']),
('user2', 'user2@example.com', '$2a$10$X9wdJ7KQsRgKpRpJvLJ5QeGpH8hV7bR0T9vD2nKRqzJQzNv0WwJZ6', ARRAY['openid', 'profile', 'email', 'read', 'write'])
ON CONFLICT (username) DO NOTHING;

-- Insert sample OAuth clients
INSERT INTO clients (client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public) VALUES
('web-app-client', '$2a$10$X9wdJ7KQsRgKpRpJvLJ5QeGpH8hV7bR0T9vD2nKRqzJQzNv0WwJZ6', 'Web Application', 
 ARRAY['http://localhost:3000/callback', 'http://localhost:8080/callback'], 
 ARRAY['openid', 'profile', 'email', 'read', 'write'], 
 ARRAY['authorization_code', 'refresh_token'], false),

('mobile-app-client', '', 'Mobile Application',
 ARRAY['com.example.app://callback'],
 ARRAY['openid', 'profile', 'email', 'read'],
 ARRAY['authorization_code', 'refresh_token'], true),

('api-client', '$2a$10$X9wdJ7KQsRgKpRpJvLJ5QeGpH8hV7bR0T9vD2nKRqzJQzNv0WwJZ6', 'API Client',
 ARRAY[''],
 ARRAY['read', 'write'],
 ARRAY['client_credentials'], false),

('test-client', 'test-secret', 'Test Client',
 ARRAY['http://localhost:8080/test/callback'],
 ARRAY['openid', 'profile', 'email', 'read'],
 ARRAY['authorization_code', 'refresh_token', 'client_credentials'], false)
ON CONFLICT (client_id) DO NOTHING;