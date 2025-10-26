package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// MigrationManager handles database schema migrations
type MigrationManager struct {
	db *sql.DB
}

// Migration represents a database migration
type Migration struct {
	Version     int
	Name        string
	UpScript    string
	DownScript  string
	ExecutedAt  *time.Time
}

func NewMigrationManager(db *sql.DB) *MigrationManager {
	return &MigrationManager{db: db}
}

// InitializeMigrationTable creates the migrations tracking table
func (m *MigrationManager) InitializeMigrationTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			executed_at TIMESTAMP DEFAULT NOW(),
			checksum VARCHAR(64) NOT NULL
		);
		
		CREATE INDEX IF NOT EXISTS idx_schema_migrations_version ON schema_migrations(version);
	`
	
	_, err := m.db.ExecContext(ctx, query)
	return err
}

// GetAppliedMigrations returns all applied migrations
func (m *MigrationManager) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	query := `SELECT version, name, executed_at FROM schema_migrations ORDER BY version`
	
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var migrations []Migration
	for rows.Next() {
		var migration Migration
		err := rows.Scan(&migration.Version, &migration.Name, &migration.ExecutedAt)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, migration)
	}
	
	return migrations, rows.Err()
}

// ApplyMigration applies a single migration
func (m *MigrationManager) ApplyMigration(ctx context.Context, migration Migration) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	
	// Execute the migration script
	_, err = tx.ExecContext(ctx, migration.UpScript)
	if err != nil {
		return fmt.Errorf("failed to execute migration %d: %w", migration.Version, err)
	}
	
	// Record the migration as applied
	insertQuery := `INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`
	checksum := generateChecksum(migration.UpScript)
	_, err = tx.ExecContext(ctx, insertQuery, migration.Version, migration.Name, checksum)
	if err != nil {
		return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
	}
	
	return tx.Commit()
}

// RollbackMigration rolls back a migration
func (m *MigrationManager) RollbackMigration(ctx context.Context, migration Migration) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	
	// Execute the rollback script
	_, err = tx.ExecContext(ctx, migration.DownScript)
	if err != nil {
		return fmt.Errorf("failed to rollback migration %d: %w", migration.Version, err)
	}
	
	// Remove the migration record
	deleteQuery := `DELETE FROM schema_migrations WHERE version = $1`
	_, err = tx.ExecContext(ctx, deleteQuery, migration.Version)
	if err != nil {
		return fmt.Errorf("failed to remove migration record %d: %w", migration.Version, err)
	}
	
	return tx.Commit()
}

// GetPendingMigrations returns migrations that haven't been applied
func (m *MigrationManager) GetPendingMigrations(ctx context.Context, allMigrations []Migration) ([]Migration, error) {
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}
	
	appliedMap := make(map[int]bool)
	for _, migration := range applied {
		appliedMap[migration.Version] = true
	}
	
	var pending []Migration
	for _, migration := range allMigrations {
		if !appliedMap[migration.Version] {
			pending = append(pending, migration)
		}
	}
	
	return pending, nil
}

// generateChecksum creates a checksum for migration validation
func generateChecksum(script string) string {
	// Simple checksum implementation - in production, use crypto/sha256
	sum := 0
	for _, char := range script {
		sum += int(char)
	}
	return fmt.Sprintf("%x", sum)
}

// GetAllMigrations returns all available migrations
func GetAllMigrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "initial_schema",
			UpScript: `
				CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
				
				CREATE TABLE IF NOT EXISTS users (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					username VARCHAR(255) UNIQUE NOT NULL,
					email VARCHAR(255) UNIQUE NOT NULL,
					password VARCHAR(255) NOT NULL,
					scopes TEXT[] DEFAULT '{}',
					created_at TIMESTAMP DEFAULT NOW(),
					updated_at TIMESTAMP DEFAULT NOW()
				);
				
				CREATE TABLE IF NOT EXISTS clients (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					client_id VARCHAR(255) UNIQUE NOT NULL,
					client_secret VARCHAR(255),
					name VARCHAR(255) NOT NULL,
					redirect_uris TEXT[] NOT NULL DEFAULT '{}',
					scopes TEXT[] NOT NULL DEFAULT '{}',
					grant_types TEXT[] NOT NULL DEFAULT '{}',
					is_public BOOLEAN DEFAULT FALSE,
					created_at TIMESTAMP DEFAULT NOW(),
					updated_at TIMESTAMP DEFAULT NOW()
				);
				
				CREATE TABLE IF NOT EXISTS authorization_codes (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					code VARCHAR(255) UNIQUE NOT NULL,
					client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
					user_id UUID NOT NULL REFERENCES users(id),
					redirect_uri VARCHAR(512) NOT NULL,
					scopes TEXT[] DEFAULT '{}',
					code_challenge VARCHAR(128),
					code_challenge_method VARCHAR(10),
					expires_at TIMESTAMP NOT NULL,
					used BOOLEAN DEFAULT FALSE,
					created_at TIMESTAMP DEFAULT NOW()
				);
				
				CREATE TABLE IF NOT EXISTS access_tokens (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					token TEXT UNIQUE NOT NULL,
					client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
					user_id UUID NOT NULL REFERENCES users(id),
					scopes TEXT[] DEFAULT '{}',
					expires_at TIMESTAMP NOT NULL,
					revoked BOOLEAN DEFAULT FALSE,
					created_at TIMESTAMP DEFAULT NOW()
				);
				
				CREATE TABLE IF NOT EXISTS refresh_tokens (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					token VARCHAR(255) UNIQUE NOT NULL,
					access_token_id UUID NOT NULL REFERENCES access_tokens(id),
					client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
					user_id UUID NOT NULL REFERENCES users(id),
					scopes TEXT[] DEFAULT '{}',
					expires_at TIMESTAMP NOT NULL,
					revoked BOOLEAN DEFAULT FALSE,
					created_at TIMESTAMP DEFAULT NOW()
				);
				
				CREATE TABLE IF NOT EXISTS device_codes (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					device_code VARCHAR(255) UNIQUE NOT NULL,
					user_code VARCHAR(20) UNIQUE NOT NULL,
					verification_uri VARCHAR(512) NOT NULL,
					verification_uri_complete VARCHAR(512),
					client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
					scopes TEXT[] DEFAULT '{}',
					expires_at TIMESTAMP NOT NULL,
					interval_seconds INTEGER DEFAULT 5,
					user_id UUID REFERENCES users(id),
					authorized BOOLEAN DEFAULT FALSE,
					access_token_id UUID REFERENCES access_tokens(id),
					created_at TIMESTAMP DEFAULT NOW()
				);
			`,
			DownScript: `
				DROP TABLE IF EXISTS device_codes;
				DROP TABLE IF EXISTS refresh_tokens;
				DROP TABLE IF EXISTS access_tokens;
				DROP TABLE IF EXISTS authorization_codes;
				DROP TABLE IF EXISTS clients;
				DROP TABLE IF EXISTS users;
			`,
		},
		{
			Version: 2,
			Name:    "add_token_security_enhancements",
			UpScript: `
				-- Add token hashing for security
				ALTER TABLE access_tokens 
				ADD COLUMN IF NOT EXISTS token_hash VARCHAR(64),
				ADD COLUMN IF NOT EXISTS token_prefix VARCHAR(10),
				ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;
				
				-- Add revoked_at to refresh tokens
				ALTER TABLE refresh_tokens 
				ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;
				
				-- Create new index on token hash
				CREATE INDEX IF NOT EXISTS idx_access_tokens_hash ON access_tokens(token_hash);
				CREATE INDEX IF NOT EXISTS idx_access_tokens_prefix ON access_tokens(token_prefix);
				
				-- Remove old token index
				DROP INDEX IF EXISTS access_tokens_token_key;
			`,
			DownScript: `
				ALTER TABLE access_tokens 
				DROP COLUMN IF EXISTS token_hash,
				DROP COLUMN IF EXISTS token_prefix,
				DROP COLUMN IF EXISTS revoked_at;
				
				ALTER TABLE refresh_tokens 
				DROP COLUMN IF EXISTS revoked_at;
				
				DROP INDEX IF EXISTS idx_access_tokens_hash;
				DROP INDEX IF EXISTS idx_access_tokens_prefix;
			`,
		},
		{
			Version: 3,
			Name:    "add_performance_indexes",
			UpScript: `
				-- Performance indexes
				CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
				CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
				CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);
				CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code);
				CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
				CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_user ON authorization_codes(client_id, user_id);
				CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);
				CREATE INDEX IF NOT EXISTS idx_access_tokens_client_user ON access_tokens(client_id, user_id);
				CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
				CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
				CREATE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code);
				CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
				CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);

				-- Partial indexes for active records only
				CREATE INDEX IF NOT EXISTS idx_authorization_codes_active ON authorization_codes(code, expires_at) WHERE used = false;
				CREATE INDEX IF NOT EXISTS idx_access_tokens_active ON access_tokens(token_hash) WHERE revoked = false;
				CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active ON refresh_tokens(token) WHERE revoked = false;
				CREATE INDEX IF NOT EXISTS idx_device_codes_pending ON device_codes(user_code) WHERE authorized = false;
			`,
			DownScript: `
				DROP INDEX IF EXISTS idx_users_username;
				DROP INDEX IF EXISTS idx_users_email;
				DROP INDEX IF EXISTS idx_clients_client_id;
				DROP INDEX IF EXISTS idx_authorization_codes_code;
				DROP INDEX IF EXISTS idx_authorization_codes_expires_at;
				DROP INDEX IF EXISTS idx_authorization_codes_client_user;
				DROP INDEX IF EXISTS idx_access_tokens_expires_at;
				DROP INDEX IF EXISTS idx_access_tokens_client_user;
				DROP INDEX IF EXISTS idx_refresh_tokens_token;
				DROP INDEX IF EXISTS idx_refresh_tokens_expires_at;
				DROP INDEX IF EXISTS idx_device_codes_device_code;
				DROP INDEX IF EXISTS idx_device_codes_user_code;
				DROP INDEX IF EXISTS idx_device_codes_expires_at;
				DROP INDEX IF EXISTS idx_authorization_codes_active;
				DROP INDEX IF EXISTS idx_access_tokens_active;
				DROP INDEX IF EXISTS idx_refresh_tokens_active;
				DROP INDEX IF EXISTS idx_device_codes_pending;
			`,
		},
		{
			Version: 4,
			Name:    "add_client_secret_rotation",
			UpScript: `
				-- Create client_secrets table for secret rotation support
				CREATE TABLE IF NOT EXISTS client_secrets (
					id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
					client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
					secret_hash TEXT NOT NULL,
					created_at TIMESTAMP NOT NULL DEFAULT NOW(),
					expires_at TIMESTAMP,
					rotated_at TIMESTAMP,
					revoked_at TIMESTAMP,
					is_primary BOOLEAN NOT NULL DEFAULT false,
					updated_at TIMESTAMP NOT NULL DEFAULT NOW()
				);

				-- Create indexes for efficient secret lookups
				CREATE INDEX IF NOT EXISTS idx_client_secrets_client_id ON client_secrets(client_id);
				CREATE INDEX IF NOT EXISTS idx_client_secrets_expires_at ON client_secrets(expires_at);
				CREATE INDEX IF NOT EXISTS idx_client_secrets_primary ON client_secrets(client_id, is_primary) WHERE is_primary = true;
				CREATE INDEX IF NOT EXISTS idx_client_secrets_active ON client_secrets(client_id) WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW());

				-- Migrate existing client secrets to the new table
				-- This ensures backward compatibility
				INSERT INTO client_secrets (client_id, secret_hash, is_primary, created_at, updated_at)
				SELECT id, client_secret, true, created_at, updated_at
				FROM clients
				WHERE client_secret IS NOT NULL AND client_secret != '';

				-- Add trigger to update updated_at timestamp
				CREATE OR REPLACE FUNCTION update_client_secrets_updated_at()
				RETURNS TRIGGER AS $$
				BEGIN
					NEW.updated_at = NOW();
					RETURN NEW;
				END;
				$$ LANGUAGE plpgsql;

				CREATE TRIGGER trigger_update_client_secrets_updated_at
					BEFORE UPDATE ON client_secrets
					FOR EACH ROW
					EXECUTE FUNCTION update_client_secrets_updated_at();
			`,
			DownScript: `
				DROP TRIGGER IF EXISTS trigger_update_client_secrets_updated_at ON client_secrets;
				DROP FUNCTION IF EXISTS update_client_secrets_updated_at();
				DROP INDEX IF EXISTS idx_client_secrets_active;
				DROP INDEX IF EXISTS idx_client_secrets_primary;
				DROP INDEX IF EXISTS idx_client_secrets_expires_at;
				DROP INDEX IF EXISTS idx_client_secrets_client_id;
				DROP TABLE IF EXISTS client_secrets;
			`,
		},
	}
}