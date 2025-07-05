package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"oauth-server/internal/config"
)

// EnhancedDatabase provides production-ready database implementation with
// connection pooling, context support, and transaction management
type EnhancedDatabase struct {
	db     *sql.DB
	config *config.DatabaseConfig
}

// Transaction wraps a database transaction
type DatabaseTransaction struct {
	tx *sql.Tx
	db *EnhancedDatabase
}

func NewEnhancedDatabase(cfg *config.DatabaseConfig) (*EnhancedDatabase, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.QueryTimeout)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &EnhancedDatabase{
		db:     db,
		config: cfg,
	}

	// Create tables with context
	if err := database.createTablesWithIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return database, nil
}

func (d *EnhancedDatabase) Close() error {
	return d.db.Close()
}

func (d *EnhancedDatabase) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

// BeginTx starts a new transaction
func (d *EnhancedDatabase) BeginTx(ctx context.Context) (Transaction, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	
	return &DatabaseTransaction{tx: tx, db: d}, nil
}

// Transaction methods
func (t *DatabaseTransaction) Commit() error {
	return t.tx.Commit()
}

func (t *DatabaseTransaction) Rollback() error {
	return t.tx.Rollback()
}

func (d *EnhancedDatabase) createTablesWithIndexes(ctx context.Context) error {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			scopes TEXT[] DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		
		// Clients table
		`CREATE TABLE IF NOT EXISTS clients (
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
		);`,
		
		// Authorization codes table
		`CREATE TABLE IF NOT EXISTS authorization_codes (
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
		);`,
		
		// Access tokens table (with token hash for security)
		`CREATE TABLE IF NOT EXISTS access_tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			token_hash VARCHAR(64) UNIQUE NOT NULL,
			token_prefix VARCHAR(10) NOT NULL,
			client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
			user_id UUID NOT NULL REFERENCES users(id),
			scopes TEXT[] DEFAULT '{}',
			expires_at TIMESTAMP NOT NULL,
			revoked BOOLEAN DEFAULT FALSE,
			revoked_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		
		// Refresh tokens table
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			token VARCHAR(255) UNIQUE NOT NULL,
			access_token_id UUID NOT NULL REFERENCES access_tokens(id),
			client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
			user_id UUID NOT NULL REFERENCES users(id),
			scopes TEXT[] DEFAULT '{}',
			expires_at TIMESTAMP NOT NULL,
			revoked BOOLEAN DEFAULT FALSE,
			revoked_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		
		// Device codes table
		`CREATE TABLE IF NOT EXISTS device_codes (
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
		);`,

		// Performance indexes
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code);`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_user ON authorization_codes(client_id, user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_hash ON access_tokens(token_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_prefix ON access_tokens(token_prefix);`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client_user ON access_tokens(client_id, user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code);`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);`,

		// Partial indexes for active records only
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_active ON authorization_codes(code, expires_at) WHERE used = false;`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_active ON access_tokens(token_hash) WHERE revoked = false;`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active ON refresh_tokens(token) WHERE revoked = false;`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_pending ON device_codes(user_code) WHERE authorized = false;`,
	}

	for _, query := range queries {
		if _, err := d.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// GetDatabaseStats returns database connection pool statistics
func (d *EnhancedDatabase) GetDatabaseStats(ctx context.Context) (*DatabaseStats, error) {
	stats := d.db.Stats()
	return &DatabaseStats{
		OpenConnections:    stats.OpenConnections,
		InUse:             stats.InUse,
		Idle:              stats.Idle,
		WaitCount:         stats.WaitCount,
		WaitDuration:      int64(stats.WaitDuration),
		MaxIdleClosed:     stats.MaxIdleClosed,
		MaxIdleTimeClosed: stats.MaxIdleTimeClosed,
		MaxLifetimeClosed: stats.MaxLifetimeClosed,
	}, nil
}

// execWithTimeout executes a query with the configured timeout
func (d *EnhancedDatabase) execWithTimeout(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, d.config.QueryTimeout)
	defer cancel()
	return d.db.ExecContext(ctx, query, args...)
}

// queryRowWithTimeout executes a query row with the configured timeout
func (d *EnhancedDatabase) queryRowWithTimeout(ctx context.Context, query string, args ...interface{}) *sql.Row {
	ctx, cancel := context.WithTimeout(ctx, d.config.QueryTimeout)
	defer cancel()
	return d.db.QueryRowContext(ctx, query, args...)
}

// queryWithTimeout executes a query with the configured timeout
func (d *EnhancedDatabase) queryWithTimeout(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	ctx, cancel := context.WithTimeout(ctx, d.config.QueryTimeout)
	defer cancel()
	return d.db.QueryContext(ctx, query, args...)
}