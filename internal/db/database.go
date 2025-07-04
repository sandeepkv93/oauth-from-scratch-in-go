package db

import (
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
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS scopes (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) UNIQUE NOT NULL,
			description TEXT,
			is_default BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW()
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
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

func (d *Database) CreateUser(user *User) error {
	query := `INSERT INTO users (username, email, password, scopes) 
			  VALUES ($1, $2, $3, $4) 
			  RETURNING id, created_at, updated_at`
	
	err := d.db.QueryRow(query, user.Username, user.Email, user.Password, 
		pq.Array(user.Scopes)).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	
	return err
}

func (d *Database) GetUserByUsername(username string) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password, scopes, created_at, updated_at 
			  FROM users WHERE username = $1`
	
	var scopes pq.StringArray
	err := d.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, 
		&scopes, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Scopes = []string(scopes)
	return user, nil
}

func (d *Database) GetUserByID(id uuid.UUID) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password, scopes, created_at, updated_at 
			  FROM users WHERE id = $1`
	
	var scopes pq.StringArray
	err := d.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, 
		&scopes, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Scopes = []string(scopes)
	return user, nil
}

func (d *Database) CreateClient(client *Client) error {
	query := `INSERT INTO clients (client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7) 
			  RETURNING id, created_at, updated_at`
	
	err := d.db.QueryRow(query, client.ClientID, client.ClientSecret, client.Name,
		pq.Array(client.RedirectURIs), pq.Array(client.Scopes), 
		pq.Array(client.GrantTypes), client.IsPublic).Scan(
		&client.ID, &client.CreatedAt, &client.UpdatedAt)
	
	return err
}

func (d *Database) GetClientByID(clientID string) (*Client, error) {
	client := &Client{}
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, created_at, updated_at 
			  FROM clients WHERE client_id = $1`
	
	var redirectURIs, scopes, grantTypes pq.StringArray
	err := d.db.QueryRow(query, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
		&redirectURIs, &scopes, &grantTypes, &client.IsPublic,
		&client.CreatedAt, &client.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	client.RedirectURIs = []string(redirectURIs)
	client.Scopes = []string(scopes)
	client.GrantTypes = []string(grantTypes)
	return client, nil
}

func (d *Database) GetAllClients() ([]*Client, error) {
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, created_at, updated_at 
			  FROM clients ORDER BY created_at DESC`
	
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var clients []*Client
	for rows.Next() {
		client := &Client{}
		var redirectURIs, scopes, grantTypes pq.StringArray
		
		err := rows.Scan(
			&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
			&redirectURIs, &scopes, &grantTypes, &client.IsPublic,
			&client.CreatedAt, &client.UpdatedAt)
		
		if err != nil {
			return nil, err
		}
		
		client.RedirectURIs = []string(redirectURIs)
		client.Scopes = []string(scopes)
		client.GrantTypes = []string(grantTypes)
		clients = append(clients, client)
	}
	
	return clients, nil
}

func (d *Database) CreateAuthorizationCode(code *AuthorizationCode) error {
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRow(query, code.Code, code.ClientID, code.UserID,
		code.RedirectURI, pq.Array(code.Scopes), code.CodeChallenge, 
		code.CodeChallengeMethod, code.ExpiresAt).Scan(
		&code.ID, &code.CreatedAt)
	
	return err
}

func (d *Database) GetAuthorizationCode(code string) (*AuthorizationCode, error) {
	authCode := &AuthorizationCode{}
	query := `SELECT id, code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, used, created_at 
			  FROM authorization_codes WHERE code = $1 AND NOT used AND expires_at > NOW()`
	
	var scopes pq.StringArray
	err := d.db.QueryRow(query, code).Scan(
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

func (d *Database) MarkAuthorizationCodeUsed(code string) error {
	query := `UPDATE authorization_codes SET used = TRUE WHERE code = $1`
	_, err := d.db.Exec(query, code)
	return err
}

func (d *Database) CreateAccessToken(token *AccessToken) error {
	query := `INSERT INTO access_tokens (token, client_id, user_id, scopes, expires_at) 
			  VALUES ($1, $2, $3, $4, $5) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRow(query, token.Token, token.ClientID, token.UserID,
		pq.Array(token.Scopes), token.ExpiresAt).Scan(
		&token.ID, &token.CreatedAt)
	
	return err
}

func (d *Database) CreateRefreshToken(token *RefreshToken) error {
	query := `INSERT INTO refresh_tokens (token, access_token_id, client_id, user_id, scopes, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6) 
			  RETURNING id, created_at`
	
	err := d.db.QueryRow(query, token.Token, token.AccessTokenID, token.ClientID,
		token.UserID, pq.Array(token.Scopes), token.ExpiresAt).Scan(
		&token.ID, &token.CreatedAt)
	
	return err
}

func (d *Database) GetAccessToken(token string) (*AccessToken, error) {
	accessToken := &AccessToken{}
	query := `SELECT id, token, client_id, user_id, scopes, expires_at, revoked, created_at 
			  FROM access_tokens WHERE token = $1 AND NOT revoked AND expires_at > NOW()`
	
	var scopes pq.StringArray
	err := d.db.QueryRow(query, token).Scan(
		&accessToken.ID, &accessToken.Token, &accessToken.ClientID, &accessToken.UserID,
		&scopes, &accessToken.ExpiresAt, &accessToken.Revoked, &accessToken.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	accessToken.Scopes = []string(scopes)
	return accessToken, nil
}

func (d *Database) GetRefreshToken(token string) (*RefreshToken, error) {
	refreshToken := &RefreshToken{}
	query := `SELECT id, token, access_token_id, client_id, user_id, scopes, expires_at, revoked, created_at 
			  FROM refresh_tokens WHERE token = $1 AND NOT revoked AND expires_at > NOW()`
	
	var scopes pq.StringArray
	err := d.db.QueryRow(query, token).Scan(
		&refreshToken.ID, &refreshToken.Token, &refreshToken.AccessTokenID,
		&refreshToken.ClientID, &refreshToken.UserID, &scopes, &refreshToken.ExpiresAt,
		&refreshToken.Revoked, &refreshToken.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	refreshToken.Scopes = []string(scopes)
	return refreshToken, nil
}

func (d *Database) RevokeAccessToken(tokenID uuid.UUID) error {
	query := `UPDATE access_tokens SET revoked = TRUE WHERE id = $1`
	_, err := d.db.Exec(query, tokenID)
	return err
}

func (d *Database) RevokeRefreshToken(token string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1`
	_, err := d.db.Exec(query, token)
	return err
}