package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/google/uuid"
	"oauth-server/internal/config"
)

type Database struct {
	db *sql.DB
}

func NewDatabase(cfg *config.DatabaseConfig) (*Database, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	database := &Database{db: db}
	if err := database.createTables(); err != nil {
		return nil, err
	}

	return database, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) createTables() error {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			scopes TEXT[] DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		
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
			updated_at TIMESTAMP DEFAULT NOW(),
			-- Dynamic Client Registration fields (RFC 7591)
			client_name VARCHAR(255),
			client_uri VARCHAR(512),
			logo_uri VARCHAR(512),
			contacts TEXT[] DEFAULT '{}',
			tos_uri VARCHAR(512),
			policy_uri VARCHAR(512),
			jwks_uri VARCHAR(512),
			jwks TEXT,
			software_id VARCHAR(255),
			software_version VARCHAR(255),
			token_endpoint_auth_method VARCHAR(100) DEFAULT 'client_secret_basic',
			response_types TEXT[] DEFAULT '{}',
			client_secret_expires_at TIMESTAMP,
			registration_access_token VARCHAR(512),
			registration_client_uri VARCHAR(512),
			client_id_issued_at TIMESTAMP DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS scopes (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) UNIQUE NOT NULL,
			description TEXT,
			category VARCHAR(100) DEFAULT 'general',
			parent_scope VARCHAR(255) REFERENCES scopes(name),
			is_default BOOLEAN DEFAULT FALSE,
			is_system BOOLEAN DEFAULT FALSE,
			requires_consent BOOLEAN DEFAULT TRUE,
			icon_url VARCHAR(512),
			display_order INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS scope_consents (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL REFERENCES users(id),
			client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
			scope VARCHAR(255) NOT NULL REFERENCES scopes(name),
			granted BOOLEAN NOT NULL DEFAULT FALSE,
			expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(user_id, client_id, scope)
		);`,
		
		`CREATE TABLE IF NOT EXISTS scope_groups (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) UNIQUE NOT NULL,
			description TEXT,
			display_name VARCHAR(255) NOT NULL,
			icon_url VARCHAR(512),
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS scope_group_memberships (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			scope_id UUID NOT NULL REFERENCES scopes(id),
			group_id UUID NOT NULL REFERENCES scope_groups(id),
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_id, group_id)
		);`,
		
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
		
		`CREATE TABLE IF NOT EXISTS access_tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			token TEXT UNIQUE NOT NULL,
			client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
			user_id UUID NOT NULL REFERENCES users(id),
			scopes TEXT[] DEFAULT '{}',
			expires_at TIMESTAMP NOT NULL,
			revoked BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			token VARCHAR(255) UNIQUE NOT NULL,
			access_token_id UUID NOT NULL REFERENCES access_tokens(id),
			client_id VARCHAR(255) NOT NULL REFERENCES clients(client_id),
			user_id UUID NOT NULL REFERENCES users(id),
			scopes TEXT[] DEFAULT '{}',
			expires_at TIMESTAMP NOT NULL,
			revoked BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		
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
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

func (d *Database) CreateUser(ctx context.Context, user *User) error {
	query := `INSERT INTO users (username, email, password, scopes) 
			  VALUES ($1, $2, $3, $4) 
			  RETURNING id, created_at, updated_at`
	
	err := d.db.QueryRowContext(ctx, query, user.Username, user.Email, user.Password, 
		pq.Array(user.Scopes)).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	
	return err
}

func (d *Database) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password, scopes, created_at, updated_at 
			  FROM users WHERE username = $1`
	
	var scopes pq.StringArray
	err := d.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, 
		&scopes, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Scopes = []string(scopes)
	return user, nil
}

func (d *Database) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password, scopes, created_at, updated_at 
			  FROM users WHERE id = $1`
	
	var scopes pq.StringArray
	err := d.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, 
		&scopes, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Scopes = []string(scopes)
	return user, nil
}

func (d *Database) CreateClient(ctx context.Context, client *Client) error {
	query := `INSERT INTO clients (client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public,
		client_name, client_uri, logo_uri, contacts, tos_uri, policy_uri, jwks_uri, jwks, software_id, 
		software_version, token_endpoint_auth_method, response_types, client_secret_expires_at,
		registration_access_token, registration_client_uri, client_id_issued_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) 
		RETURNING id, created_at, updated_at`
	
	err := d.db.QueryRowContext(ctx, query, client.ClientID, client.ClientSecret, client.Name,
		pq.Array(client.RedirectURIs), pq.Array(client.Scopes), 
		pq.Array(client.GrantTypes), client.IsPublic,
		client.ClientName, client.ClientURI, client.LogoURI, pq.Array(client.ContactEmails),
		client.TosURI, client.PolicyURI, client.JwksURI, client.Jwks, client.SoftwareID,
		client.SoftwareVersion, client.TokenEndpointAuthMethod, pq.Array(client.ResponseTypes),
		client.ClientSecretExpiresAt, client.RegistrationAccessToken, client.RegistrationClientURI,
		client.ClientIDIssuedAt).Scan(&client.ID, &client.CreatedAt, &client.UpdatedAt)
	
	return err
}

func (d *Database) GetClientByID(ctx context.Context, clientID string) (*Client, error) {
	client := &Client{}
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, 
		created_at, updated_at, client_name, client_uri, logo_uri, contacts, tos_uri, policy_uri,
		jwks_uri, jwks, software_id, software_version, token_endpoint_auth_method, response_types,
		client_secret_expires_at, registration_access_token, registration_client_uri, client_id_issued_at
		FROM clients WHERE client_id = $1`
	
	var redirectURIs, scopes, grantTypes, responseTypes, contacts pq.StringArray
	err := d.db.QueryRowContext(ctx, query, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
		&redirectURIs, &scopes, &grantTypes, &client.IsPublic,
		&client.CreatedAt, &client.UpdatedAt, &client.ClientName, &client.ClientURI,
		&client.LogoURI, &contacts, &client.TosURI, &client.PolicyURI,
		&client.JwksURI, &client.Jwks, &client.SoftwareID, &client.SoftwareVersion,
		&client.TokenEndpointAuthMethod, &responseTypes, &client.ClientSecretExpiresAt,
		&client.RegistrationAccessToken, &client.RegistrationClientURI, &client.ClientIDIssuedAt)
	
	if err != nil {
		return nil, err
	}
	
	client.RedirectURIs = []string(redirectURIs)
	client.Scopes = []string(scopes)
	client.GrantTypes = []string(grantTypes)
	client.ResponseTypes = []string(responseTypes)
	client.ContactEmails = []string(contacts)
	return client, nil
}

func (d *Database) GetAllClients(ctx context.Context) ([]*Client, error) {
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, 
		created_at, updated_at, client_name, client_uri, logo_uri, contacts, tos_uri, policy_uri,
		jwks_uri, jwks, software_id, software_version, token_endpoint_auth_method, response_types,
		client_secret_expires_at, registration_access_token, registration_client_uri, client_id_issued_at
		FROM clients ORDER BY created_at DESC`
	
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var clients []*Client
	for rows.Next() {
		client := &Client{}
		var redirectURIs, scopes, grantTypes, responseTypes, contacts pq.StringArray
		
		err := rows.Scan(
			&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
			&redirectURIs, &scopes, &grantTypes, &client.IsPublic,
			&client.CreatedAt, &client.UpdatedAt, &client.ClientName, &client.ClientURI,
			&client.LogoURI, &contacts, &client.TosURI, &client.PolicyURI,
			&client.JwksURI, &client.Jwks, &client.SoftwareID, &client.SoftwareVersion,
			&client.TokenEndpointAuthMethod, &responseTypes, &client.ClientSecretExpiresAt,
			&client.RegistrationAccessToken, &client.RegistrationClientURI, &client.ClientIDIssuedAt)
		
		if err != nil {
			return nil, err
		}
		
		client.RedirectURIs = []string(redirectURIs)
		client.Scopes = []string(scopes)
		client.GrantTypes = []string(grantTypes)
		client.ResponseTypes = []string(responseTypes)
		client.ContactEmails = []string(contacts)
		clients = append(clients, client)
	}
	
	return clients, nil
}

// Dynamic Client Registration operations (RFC 7591)

func (d *Database) UpdateClient(ctx context.Context, client *Client) error {
	query := `UPDATE clients SET 
		client_secret = $2, name = $3, redirect_uris = $4, scopes = $5, 
		grant_types = $6, is_public = $7, updated_at = $8,
		client_name = $9, client_uri = $10, logo_uri = $11, contacts = $12,
		tos_uri = $13, policy_uri = $14, jwks_uri = $15, jwks = $16,
		software_id = $17, software_version = $18, token_endpoint_auth_method = $19,
		response_types = $20, client_secret_expires_at = $21,
		registration_access_token = $22, registration_client_uri = $23
		WHERE client_id = $1`
	
	_, err := d.db.ExecContext(ctx, query, 
		client.ClientID, client.ClientSecret, client.Name,
		pq.Array(client.RedirectURIs), pq.Array(client.Scopes), 
		pq.Array(client.GrantTypes), client.IsPublic, client.UpdatedAt,
		client.ClientName, client.ClientURI, client.LogoURI, pq.Array(client.ContactEmails),
		client.TosURI, client.PolicyURI, client.JwksURI, client.Jwks,
		client.SoftwareID, client.SoftwareVersion, client.TokenEndpointAuthMethod,
		pq.Array(client.ResponseTypes), client.ClientSecretExpiresAt,
		client.RegistrationAccessToken, client.RegistrationClientURI)
	
	return err
}

func (d *Database) DeleteClient(ctx context.Context, clientID string) error {
	// First, clean up related records
	queries := []string{
		`DELETE FROM refresh_tokens WHERE client_id = $1`,
		`DELETE FROM access_tokens WHERE client_id = $1`,
		`DELETE FROM authorization_codes WHERE client_id = $1`,
		`DELETE FROM device_codes WHERE client_id = $1`,
		`DELETE FROM scope_consents WHERE client_id = $1`,
		`DELETE FROM clients WHERE client_id = $1`,
	}
	
	for _, query := range queries {
		_, err := d.db.ExecContext(ctx, query, clientID)
		if err != nil {
			return err
		}
	}
	
	return nil
}

func (d *Database) GetClientByRegistrationToken(ctx context.Context, token string) (*Client, error) {
	client := &Client{}
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, 
		created_at, updated_at, client_name, client_uri, logo_uri, contacts, tos_uri, policy_uri,
		jwks_uri, jwks, software_id, software_version, token_endpoint_auth_method, response_types,
		client_secret_expires_at, registration_access_token, registration_client_uri, client_id_issued_at
		FROM clients WHERE registration_access_token = $1`
	
	var redirectURIs, scopes, grantTypes, responseTypes, contacts pq.StringArray
	err := d.db.QueryRowContext(ctx, query, token).Scan(
		&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
		&redirectURIs, &scopes, &grantTypes, &client.IsPublic,
		&client.CreatedAt, &client.UpdatedAt, &client.ClientName, &client.ClientURI,
		&client.LogoURI, &contacts, &client.TosURI, &client.PolicyURI,
		&client.JwksURI, &client.Jwks, &client.SoftwareID, &client.SoftwareVersion,
		&client.TokenEndpointAuthMethod, &responseTypes, &client.ClientSecretExpiresAt,
		&client.RegistrationAccessToken, &client.RegistrationClientURI, &client.ClientIDIssuedAt)
	
	if err != nil {
		return nil, err
	}
	
	client.RedirectURIs = []string(redirectURIs)
	client.Scopes = []string(scopes)
	client.GrantTypes = []string(grantTypes)
	client.ResponseTypes = []string(responseTypes)
	client.ContactEmails = []string(contacts)
	return client, nil
}

func (d *Database) CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRowContext(ctx, query, code.Code, code.ClientID, code.UserID,
		code.RedirectURI, pq.Array(code.Scopes), code.CodeChallenge, 
		code.CodeChallengeMethod, code.ExpiresAt).Scan(
		&code.ID, &code.CreatedAt)
	
	return err
}

func (d *Database) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	authCode := &AuthorizationCode{}
	query := `SELECT id, code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, used, created_at 
			  FROM authorization_codes WHERE code = $1 AND NOT used AND expires_at > NOW()`
	
	var scopes pq.StringArray
	err := d.db.QueryRowContext(ctx, query, code).Scan(
		&authCode.ID, &authCode.Code, &authCode.ClientID, &authCode.UserID,
		&authCode.RedirectURI, &scopes, &authCode.CodeChallenge, 
		&authCode.CodeChallengeMethod, &authCode.ExpiresAt, &authCode.Used,
		&authCode.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	authCode.Scopes = []string(scopes)
	return authCode, nil
}

func (d *Database) MarkAuthorizationCodeUsed(ctx context.Context, code string) error {
	query := `UPDATE authorization_codes SET used = TRUE WHERE code = $1`
	_, err := d.db.ExecContext(ctx, query, code)
	return err
}

func (d *Database) CreateAccessToken(ctx context.Context, token *AccessToken) error {
	query := `INSERT INTO access_tokens (token, client_id, user_id, scopes, expires_at) 
			  VALUES ($1, $2, $3, $4, $5) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRowContext(ctx, query, token.Token, token.ClientID, token.UserID,
		pq.Array(token.Scopes), token.ExpiresAt).Scan(
		&token.ID, &token.CreatedAt)
	
	return err
}

func (d *Database) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `INSERT INTO refresh_tokens (token, access_token_id, client_id, user_id, scopes, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRowContext(ctx, query, token.Token, token.AccessTokenID, token.ClientID,
		token.UserID, pq.Array(token.Scopes), token.ExpiresAt).Scan(
		&token.ID, &token.CreatedAt)
	
	return err
}

func (d *Database) GetAccessToken(ctx context.Context, token string) (*AccessToken, error) {
	accessToken := &AccessToken{}
	query := `SELECT id, token, client_id, user_id, scopes, expires_at, revoked, created_at 
			  FROM access_tokens WHERE token = $1 AND NOT revoked AND expires_at > NOW()`
	
	var scopes pq.StringArray
	err := d.db.QueryRowContext(ctx, query, token).Scan(
		&accessToken.ID, &accessToken.Token, &accessToken.ClientID, &accessToken.UserID,
		&scopes, &accessToken.ExpiresAt, &accessToken.Revoked, &accessToken.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	accessToken.Scopes = []string(scopes)
	return accessToken, nil
}

func (d *Database) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	refreshToken := &RefreshToken{}
	query := `SELECT id, token, access_token_id, client_id, user_id, scopes, expires_at, revoked, created_at 
			  FROM refresh_tokens WHERE token = $1 AND NOT revoked AND expires_at > NOW()`
	
	var scopes pq.StringArray
	err := d.db.QueryRowContext(ctx, query, token).Scan(
		&refreshToken.ID, &refreshToken.Token, &refreshToken.AccessTokenID,
		&refreshToken.ClientID, &refreshToken.UserID, &scopes, &refreshToken.ExpiresAt,
		&refreshToken.Revoked, &refreshToken.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	refreshToken.Scopes = []string(scopes)
	return refreshToken, nil
}

func (d *Database) RevokeAccessToken(ctx context.Context, tokenID uuid.UUID) error {
	query := `UPDATE access_tokens SET revoked = TRUE WHERE id = $1`
	_, err := d.db.ExecContext(ctx, query, tokenID)
	return err
}

func (d *Database) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1`
	_, err := d.db.ExecContext(ctx, query, token)
	return err
}

func (d *Database) CreateDeviceCode(ctx context.Context, deviceCode *DeviceCode) error {
	query := `INSERT INTO device_codes (device_code, user_code, verification_uri, verification_uri_complete, client_id, scopes, expires_at, interval_seconds) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRowContext(ctx, query, deviceCode.DeviceCode, deviceCode.UserCode, deviceCode.VerificationURI,
		deviceCode.VerificationURIComplete, deviceCode.ClientID, pq.Array(deviceCode.Scopes), 
		deviceCode.ExpiresAt, deviceCode.Interval).Scan(
		&deviceCode.ID, &deviceCode.CreatedAt)
	
	return err
}

func (d *Database) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	device := &DeviceCode{}
	query := `SELECT id, device_code, user_code, verification_uri, verification_uri_complete, client_id, scopes, expires_at, interval_seconds, user_id, authorized, access_token_id, created_at 
			  FROM device_codes WHERE device_code = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	var userID, accessTokenID *uuid.UUID
	err := d.db.QueryRowContext(ctx, query, deviceCode).Scan(
		&device.ID, &device.DeviceCode, &device.UserCode, &device.VerificationURI,
		&device.VerificationURIComplete, &device.ClientID, &scopes, &device.ExpiresAt,
		&device.Interval, &userID, &device.Authorized, &accessTokenID, &device.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	device.Scopes = []string(scopes)
	device.UserID = userID
	device.AccessTokenID = accessTokenID
	return device, nil
}

func (d *Database) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	device := &DeviceCode{}
	query := `SELECT id, device_code, user_code, verification_uri, verification_uri_complete, client_id, scopes, expires_at, interval_seconds, user_id, authorized, access_token_id, created_at 
			  FROM device_codes WHERE user_code = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	var userID, accessTokenID *uuid.UUID
	err := d.db.QueryRowContext(ctx, query, userCode).Scan(
		&device.ID, &device.DeviceCode, &device.UserCode, &device.VerificationURI,
		&device.VerificationURIComplete, &device.ClientID, &scopes, &device.ExpiresAt,
		&device.Interval, &userID, &device.Authorized, &accessTokenID, &device.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	device.Scopes = []string(scopes)
	device.UserID = userID
	device.AccessTokenID = accessTokenID
	return device, nil
}

func (d *Database) AuthorizeDeviceCode(ctx context.Context, userCode string, userID uuid.UUID) error {
	query := `UPDATE device_codes SET user_id = $1, authorized = TRUE WHERE user_code = $2 AND expires_at > NOW()`
	_, err := d.db.ExecContext(ctx, query, userID, userCode)
	return err
}

// CleanupExpiredTokens removes expired access and refresh tokens
func (d *Database) CleanupExpiredTokens(ctx context.Context) error {
	queries := []string{
		`DELETE FROM access_tokens WHERE expires_at < NOW()`,
		`DELETE FROM refresh_tokens WHERE expires_at < NOW()`,
	}
	
	for _, query := range queries {
		_, err := d.db.ExecContext(ctx, query)
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanupExpiredCodes removes expired authorization and device codes
func (d *Database) CleanupExpiredCodes(ctx context.Context) error {
	queries := []string{
		`DELETE FROM authorization_codes WHERE expires_at < NOW()`,
		`DELETE FROM device_codes WHERE expires_at < NOW()`,
	}
	
	for _, query := range queries {
		_, err := d.db.ExecContext(ctx, query)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetDatabaseStats returns database connection statistics
func (d *Database) GetDatabaseStats(ctx context.Context) (*DatabaseStats, error) {
	stats := d.db.Stats()
	return &DatabaseStats{
		OpenConnections:     stats.OpenConnections,
		InUse:              stats.InUse,
		Idle:               stats.Idle,
		WaitCount:          stats.WaitCount,
		WaitDuration:       int64(stats.WaitDuration),
		MaxIdleClosed:      stats.MaxIdleClosed,
		MaxIdleTimeClosed:  stats.MaxIdleTimeClosed,
		MaxLifetimeClosed:  stats.MaxLifetimeClosed,
	}, nil
}

// Ping verifies the database connection
func (d *Database) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

// Scope operations

func (d *Database) CreateScope(ctx context.Context, scope *Scope) error {
	query := `INSERT INTO scopes (id, name, description, category, parent_scope, is_default, is_system, requires_consent, icon_url, display_order, created_at, updated_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	
	_, err := d.db.ExecContext(ctx, query, scope.ID, scope.Name, scope.Description, 
		scope.Category, scope.ParentScope, scope.IsDefault, scope.IsSystem, 
		scope.RequiresConsent, scope.IconURL, scope.DisplayOrder, 
		scope.CreatedAt, scope.UpdatedAt)
	
	return err
}

func (d *Database) GetScopeByName(ctx context.Context, name string) (*Scope, error) {
	scope := &Scope{}
	query := `SELECT id, name, description, category, parent_scope, is_default, is_system, requires_consent, icon_url, display_order, created_at, updated_at 
			  FROM scopes WHERE name = $1`
	
	err := d.db.QueryRowContext(ctx, query, name).Scan(
		&scope.ID, &scope.Name, &scope.Description, &scope.Category, 
		&scope.ParentScope, &scope.IsDefault, &scope.IsSystem, 
		&scope.RequiresConsent, &scope.IconURL, &scope.DisplayOrder,
		&scope.CreatedAt, &scope.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	return scope, nil
}

func (d *Database) GetAllScopes(ctx context.Context) ([]*Scope, error) {
	query := `SELECT id, name, description, category, parent_scope, is_default, is_system, requires_consent, icon_url, display_order, created_at, updated_at 
			  FROM scopes ORDER BY display_order, name`
	
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var scopes []*Scope
	for rows.Next() {
		scope := &Scope{}
		err := rows.Scan(
			&scope.ID, &scope.Name, &scope.Description, &scope.Category,
			&scope.ParentScope, &scope.IsDefault, &scope.IsSystem,
			&scope.RequiresConsent, &scope.IconURL, &scope.DisplayOrder,
			&scope.CreatedAt, &scope.UpdatedAt)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	
	return scopes, nil
}

func (d *Database) GetScopesByCategory(ctx context.Context, category string) ([]*Scope, error) {
	query := `SELECT id, name, description, category, parent_scope, is_default, is_system, requires_consent, icon_url, display_order, created_at, updated_at 
			  FROM scopes WHERE category = $1 ORDER BY display_order, name`
	
	rows, err := d.db.QueryContext(ctx, query, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var scopes []*Scope
	for rows.Next() {
		scope := &Scope{}
		err := rows.Scan(
			&scope.ID, &scope.Name, &scope.Description, &scope.Category,
			&scope.ParentScope, &scope.IsDefault, &scope.IsSystem,
			&scope.RequiresConsent, &scope.IconURL, &scope.DisplayOrder,
			&scope.CreatedAt, &scope.UpdatedAt)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	
	return scopes, nil
}

func (d *Database) UpdateScope(ctx context.Context, scope *Scope) error {
	query := `UPDATE scopes SET description = $2, category = $3, parent_scope = $4, 
			  is_default = $5, is_system = $6, requires_consent = $7, 
			  icon_url = $8, display_order = $9, updated_at = $10 
			  WHERE name = $1`
	
	_, err := d.db.ExecContext(ctx, query, scope.Name, scope.Description, 
		scope.Category, scope.ParentScope, scope.IsDefault, scope.IsSystem,
		scope.RequiresConsent, scope.IconURL, scope.DisplayOrder, scope.UpdatedAt)
	
	return err
}

func (d *Database) DeleteScope(ctx context.Context, name string) error {
	query := `DELETE FROM scopes WHERE name = $1`
	_, err := d.db.ExecContext(ctx, query, name)
	return err
}

func (d *Database) GetDefaultScopes(ctx context.Context) ([]*Scope, error) {
	query := `SELECT id, name, description, category, parent_scope, is_default, is_system, requires_consent, icon_url, display_order, created_at, updated_at 
			  FROM scopes WHERE is_default = TRUE ORDER BY display_order, name`
	
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var scopes []*Scope
	for rows.Next() {
		scope := &Scope{}
		err := rows.Scan(
			&scope.ID, &scope.Name, &scope.Description, &scope.Category,
			&scope.ParentScope, &scope.IsDefault, &scope.IsSystem,
			&scope.RequiresConsent, &scope.IconURL, &scope.DisplayOrder,
			&scope.CreatedAt, &scope.UpdatedAt)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	
	return scopes, nil
}

// Scope consent operations

func (d *Database) CreateScopeConsent(ctx context.Context, consent *ScopeConsent) error {
	query := `INSERT INTO scope_consents (id, user_id, client_id, scope, granted, expires_at, created_at, updated_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			  ON CONFLICT (user_id, client_id, scope) 
			  DO UPDATE SET granted = $5, expires_at = $6, updated_at = $8`
	
	_, err := d.db.ExecContext(ctx, query, consent.ID, consent.UserID, 
		consent.ClientID, consent.Scope, consent.Granted, consent.ExpiresAt,
		consent.CreatedAt, consent.UpdatedAt)
	
	return err
}

func (d *Database) GetScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) (*ScopeConsent, error) {
	consent := &ScopeConsent{}
	query := `SELECT id, user_id, client_id, scope, granted, expires_at, created_at, updated_at 
			  FROM scope_consents WHERE user_id = $1 AND client_id = $2 AND scope = $3`
	
	err := d.db.QueryRowContext(ctx, query, userID, clientID, scope).Scan(
		&consent.ID, &consent.UserID, &consent.ClientID, &consent.Scope,
		&consent.Granted, &consent.ExpiresAt, &consent.CreatedAt, &consent.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	return consent, nil
}

func (d *Database) GetUserScopeConsents(ctx context.Context, userID uuid.UUID, clientID string) ([]*ScopeConsent, error) {
	query := `SELECT id, user_id, client_id, scope, granted, expires_at, created_at, updated_at 
			  FROM scope_consents WHERE user_id = $1 AND client_id = $2`
	
	rows, err := d.db.QueryContext(ctx, query, userID, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var consents []*ScopeConsent
	for rows.Next() {
		consent := &ScopeConsent{}
		err := rows.Scan(
			&consent.ID, &consent.UserID, &consent.ClientID, &consent.Scope,
			&consent.Granted, &consent.ExpiresAt, &consent.CreatedAt, &consent.UpdatedAt)
		if err != nil {
			return nil, err
		}
		consents = append(consents, consent)
	}
	
	return consents, nil
}

func (d *Database) UpdateScopeConsent(ctx context.Context, consent *ScopeConsent) error {
	query := `UPDATE scope_consents SET granted = $4, expires_at = $5, updated_at = $6 
			  WHERE user_id = $1 AND client_id = $2 AND scope = $3`
	
	_, err := d.db.ExecContext(ctx, query, consent.UserID, consent.ClientID, 
		consent.Scope, consent.Granted, consent.ExpiresAt, consent.UpdatedAt)
	
	return err
}

func (d *Database) RevokeScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) error {
	query := `DELETE FROM scope_consents WHERE user_id = $1 AND client_id = $2 AND scope = $3`
	_, err := d.db.ExecContext(ctx, query, userID, clientID, scope)
	return err
}

func (d *Database) CleanupExpiredConsents(ctx context.Context) error {
	query := `DELETE FROM scope_consents WHERE expires_at IS NOT NULL AND expires_at < NOW()`
	_, err := d.db.ExecContext(ctx, query)
	return err
}

// Scope group operations

func (d *Database) CreateScopeGroup(ctx context.Context, group *ScopeGroup) error {
	query := `INSERT INTO scope_groups (id, name, description, display_name, icon_url, created_at, updated_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`
	
	_, err := d.db.ExecContext(ctx, query, group.ID, group.Name, group.Description, 
		group.DisplayName, group.IconURL, group.CreatedAt, group.UpdatedAt)
	
	return err
}

func (d *Database) GetScopeGroup(ctx context.Context, id uuid.UUID) (*ScopeGroup, error) {
	group := &ScopeGroup{}
	query := `SELECT id, name, description, display_name, icon_url, created_at, updated_at 
			  FROM scope_groups WHERE id = $1`
	
	err := d.db.QueryRowContext(ctx, query, id).Scan(
		&group.ID, &group.Name, &group.Description, &group.DisplayName,
		&group.IconURL, &group.CreatedAt, &group.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	return group, nil
}

func (d *Database) GetAllScopeGroups(ctx context.Context) ([]*ScopeGroup, error) {
	query := `SELECT id, name, description, display_name, icon_url, created_at, updated_at 
			  FROM scope_groups ORDER BY name`
	
	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var groups []*ScopeGroup
	for rows.Next() {
		group := &ScopeGroup{}
		err := rows.Scan(
			&group.ID, &group.Name, &group.Description, &group.DisplayName,
			&group.IconURL, &group.CreatedAt, &group.UpdatedAt)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	
	return groups, nil
}

func (d *Database) UpdateScopeGroup(ctx context.Context, group *ScopeGroup) error {
	query := `UPDATE scope_groups SET description = $2, display_name = $3, 
			  icon_url = $4, updated_at = $5 WHERE id = $1`
	
	_, err := d.db.ExecContext(ctx, query, group.ID, group.Description, 
		group.DisplayName, group.IconURL, group.UpdatedAt)
	
	return err
}

func (d *Database) DeleteScopeGroup(ctx context.Context, id uuid.UUID) error {
	// First remove all memberships
	_, err := d.db.ExecContext(ctx, `DELETE FROM scope_group_memberships WHERE group_id = $1`, id)
	if err != nil {
		return err
	}
	
	// Then delete the group
	_, err = d.db.ExecContext(ctx, `DELETE FROM scope_groups WHERE id = $1`, id)
	return err
}

func (d *Database) AddScopeToGroup(ctx context.Context, scopeID, groupID uuid.UUID) error {
	query := `INSERT INTO scope_group_memberships (id, scope_id, group_id, created_at) 
			  VALUES (uuid_generate_v4(), $1, $2, NOW())
			  ON CONFLICT (scope_id, group_id) DO NOTHING`
	
	_, err := d.db.ExecContext(ctx, query, scopeID, groupID)
	return err
}

func (d *Database) RemoveScopeFromGroup(ctx context.Context, scopeID, groupID uuid.UUID) error {
	query := `DELETE FROM scope_group_memberships WHERE scope_id = $1 AND group_id = $2`
	_, err := d.db.ExecContext(ctx, query, scopeID, groupID)
	return err
}

func (d *Database) GetScopesByGroup(ctx context.Context, groupID uuid.UUID) ([]*Scope, error) {
	query := `SELECT s.id, s.name, s.description, s.category, s.parent_scope, s.is_default, s.is_system, s.requires_consent, s.icon_url, s.display_order, s.created_at, s.updated_at 
			  FROM scopes s 
			  JOIN scope_group_memberships sgm ON s.id = sgm.scope_id 
			  WHERE sgm.group_id = $1 
			  ORDER BY s.display_order, s.name`
	
	rows, err := d.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var scopes []*Scope
	for rows.Next() {
		scope := &Scope{}
		err := rows.Scan(
			&scope.ID, &scope.Name, &scope.Description, &scope.Category,
			&scope.ParentScope, &scope.IsDefault, &scope.IsSystem,
			&scope.RequiresConsent, &scope.IconURL, &scope.DisplayOrder,
			&scope.CreatedAt, &scope.UpdatedAt)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	
	return scopes, nil
}