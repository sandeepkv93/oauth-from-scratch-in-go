package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// User operations with context support
func (d *EnhancedDatabase) CreateUser(ctx context.Context, user *User) error {
	query := `INSERT INTO users (username, email, password, scopes) 
			  VALUES ($1, $2, $3, $4) 
			  RETURNING id, created_at, updated_at`
	
	row := d.queryRowWithTimeout(ctx, query, user.Username, user.Email, user.Password, 
		pq.Array(user.Scopes))
	
	return row.Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
}

func (d *EnhancedDatabase) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password, scopes, created_at, updated_at 
			  FROM users WHERE username = $1`
	
	var scopes pq.StringArray
	row := d.queryRowWithTimeout(ctx, query, username)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, 
		&scopes, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Scopes = []string(scopes)
	return user, nil
}

func (d *EnhancedDatabase) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user := &User{}
	query := `SELECT id, username, email, password, scopes, created_at, updated_at 
			  FROM users WHERE id = $1`
	
	var scopes pq.StringArray
	row := d.queryRowWithTimeout(ctx, query, id)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, 
		&scopes, &user.CreatedAt, &user.UpdatedAt)
	
	if err != nil {
		return nil, err
	}
	
	user.Scopes = []string(scopes)
	return user, nil
}

// Client operations with context support
func (d *EnhancedDatabase) CreateClient(ctx context.Context, client *Client) error {
	query := `INSERT INTO clients (client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7) 
			  RETURNING id, created_at, updated_at`
	
	row := d.queryRowWithTimeout(ctx, query, client.ClientID, client.ClientSecret, client.Name,
		pq.Array(client.RedirectURIs), pq.Array(client.Scopes), 
		pq.Array(client.GrantTypes), client.IsPublic)
	
	return row.Scan(&client.ID, &client.CreatedAt, &client.UpdatedAt)
}

func (d *EnhancedDatabase) GetClientByID(ctx context.Context, clientID string) (*Client, error) {
	client := &Client{}
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, created_at, updated_at 
			  FROM clients WHERE client_id = $1`
	
	var redirectURIs, scopes, grantTypes pq.StringArray
	row := d.queryRowWithTimeout(ctx, query, clientID)
	err := row.Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
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

func (d *EnhancedDatabase) GetAllClients(ctx context.Context) ([]*Client, error) {
	query := `SELECT id, client_id, client_secret, name, redirect_uris, scopes, grant_types, is_public, created_at, updated_at 
			  FROM clients ORDER BY created_at DESC`
	
	rows, err := d.queryWithTimeout(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var clients []*Client
	for rows.Next() {
		client := &Client{}
		var redirectURIs, scopes, grantTypes pq.StringArray
		
		err := rows.Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.Name,
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
	
	return clients, rows.Err()
}

// Authorization code operations with context support
func (d *EnhancedDatabase) CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
			  RETURNING id, created_at`
	
	row := d.queryRowWithTimeout(ctx, query, code.Code, code.ClientID, code.UserID, code.RedirectURI,
		pq.Array(code.Scopes), code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt)
	
	return row.Scan(&code.ID, &code.CreatedAt)
}

func (d *EnhancedDatabase) GetAuthorizationCode(ctx context.Context, codeStr string) (*AuthorizationCode, error) {
	code := &AuthorizationCode{}
	query := `SELECT id, code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, used, created_at 
			  FROM authorization_codes WHERE code = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	row := d.queryRowWithTimeout(ctx, query, codeStr)
	err := row.Scan(&code.ID, &code.Code, &code.ClientID, &code.UserID, &code.RedirectURI,
		&scopes, &code.CodeChallenge, &code.CodeChallengeMethod, &code.ExpiresAt, 
		&code.Used, &code.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	code.Scopes = []string(scopes)
	return code, nil
}

func (d *EnhancedDatabase) MarkAuthorizationCodeUsed(ctx context.Context, codeStr string) error {
	query := `UPDATE authorization_codes SET used = true WHERE code = $1`
	
	result, err := d.execWithTimeout(ctx, query, codeStr)
	if err != nil {
		return err
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// Token hashing utilities for security
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func getTokenPrefix(token string) string {
	if len(token) < 10 {
		return token
	}
	return token[:10]
}

// Access token operations with token hashing
func (d *EnhancedDatabase) CreateAccessToken(ctx context.Context, token *AccessToken) error {
	tokenHash := hashToken(token.Token)
	tokenPrefix := getTokenPrefix(token.Token)
	
	query := `INSERT INTO access_tokens (token_hash, token_prefix, client_id, user_id, scopes, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6) 
			  RETURNING id, created_at`
	
	row := d.queryRowWithTimeout(ctx, query, tokenHash, tokenPrefix, token.ClientID, token.UserID,
		pq.Array(token.Scopes), token.ExpiresAt)
	
	return row.Scan(&token.ID, &token.CreatedAt)
}

func (d *EnhancedDatabase) GetAccessToken(ctx context.Context, tokenStr string) (*AccessToken, error) {
	tokenHash := hashToken(tokenStr)
	
	token := &AccessToken{}
	query := `SELECT id, token_prefix, client_id, user_id, scopes, expires_at, revoked, revoked_at, created_at 
			  FROM access_tokens WHERE token_hash = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	var revokedAt sql.NullTime
	row := d.queryRowWithTimeout(ctx, query, tokenHash)
	err := row.Scan(&token.ID, &token.Token, &token.ClientID, &token.UserID, &scopes,
		&token.ExpiresAt, &token.Revoked, &revokedAt, &token.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	token.Scopes = []string(scopes)
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	return token, nil
}

func (d *EnhancedDatabase) RevokeAccessToken(ctx context.Context, tokenID uuid.UUID) error {
	query := `UPDATE access_tokens SET revoked = true, revoked_at = NOW() WHERE id = $1`
	
	result, err := d.execWithTimeout(ctx, query, tokenID)
	if err != nil {
		return err
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// Refresh token operations
func (d *EnhancedDatabase) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `INSERT INTO refresh_tokens (token, access_token_id, client_id, user_id, scopes, expires_at) 
			  VALUES ($1, $2, $3, $4, $5, $6) 
			  RETURNING id, created_at`
	
	row := d.queryRowWithTimeout(ctx, query, token.Token, token.AccessTokenID, token.ClientID, 
		token.UserID, pq.Array(token.Scopes), token.ExpiresAt)
	
	return row.Scan(&token.ID, &token.CreatedAt)
}

func (d *EnhancedDatabase) GetRefreshToken(ctx context.Context, tokenStr string) (*RefreshToken, error) {
	token := &RefreshToken{}
	query := `SELECT id, token, access_token_id, client_id, user_id, scopes, expires_at, revoked, revoked_at, created_at 
			  FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	var revokedAt sql.NullTime
	row := d.queryRowWithTimeout(ctx, query, tokenStr)
	err := row.Scan(&token.ID, &token.Token, &token.AccessTokenID, &token.ClientID, &token.UserID, 
		&scopes, &token.ExpiresAt, &token.Revoked, &revokedAt, &token.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	token.Scopes = []string(scopes)
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	return token, nil
}

func (d *EnhancedDatabase) RevokeRefreshToken(ctx context.Context, tokenStr string) error {
	query := `UPDATE refresh_tokens SET revoked = true, revoked_at = NOW() WHERE token = $1`
	
	result, err := d.execWithTimeout(ctx, query, tokenStr)
	if err != nil {
		return err
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// Device code operations
func (d *EnhancedDatabase) CreateDeviceCode(ctx context.Context, deviceCode *DeviceCode) error {
	query := `INSERT INTO device_codes (device_code, user_code, verification_uri, verification_uri_complete, client_id, scopes, expires_at, interval_seconds) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
			  RETURNING id, created_at`
	
	row := d.queryRowWithTimeout(ctx, query, deviceCode.DeviceCode, deviceCode.UserCode, 
		deviceCode.VerificationURI, deviceCode.VerificationURIComplete, deviceCode.ClientID,
		pq.Array(deviceCode.Scopes), deviceCode.ExpiresAt, deviceCode.Interval)
	
	return row.Scan(&deviceCode.ID, &deviceCode.CreatedAt)
}

func (d *EnhancedDatabase) GetDeviceCode(ctx context.Context, deviceCodeStr string) (*DeviceCode, error) {
	deviceCode := &DeviceCode{}
	query := `SELECT id, device_code, user_code, verification_uri, verification_uri_complete, client_id, scopes, expires_at, interval_seconds, user_id, authorized, access_token_id, created_at 
			  FROM device_codes WHERE device_code = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	var userID, accessTokenID sql.NullString
	row := d.queryRowWithTimeout(ctx, query, deviceCodeStr)
	err := row.Scan(&deviceCode.ID, &deviceCode.DeviceCode, &deviceCode.UserCode, 
		&deviceCode.VerificationURI, &deviceCode.VerificationURIComplete, &deviceCode.ClientID,
		&scopes, &deviceCode.ExpiresAt, &deviceCode.Interval, &userID, &deviceCode.Authorized,
		&accessTokenID, &deviceCode.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	deviceCode.Scopes = []string(scopes)
	if userID.Valid {
		uid, err := uuid.Parse(userID.String)
		if err == nil {
			deviceCode.UserID = &uid
		}
	}
	if accessTokenID.Valid {
		atid, err := uuid.Parse(accessTokenID.String)
		if err == nil {
			deviceCode.AccessTokenID = &atid
		}
	}
	
	return deviceCode, nil
}

func (d *EnhancedDatabase) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	deviceCode := &DeviceCode{}
	query := `SELECT id, device_code, user_code, verification_uri, verification_uri_complete, client_id, scopes, expires_at, interval_seconds, user_id, authorized, access_token_id, created_at 
			  FROM device_codes WHERE user_code = $1 AND expires_at > NOW()`
	
	var scopes pq.StringArray
	var userID, accessTokenID sql.NullString
	row := d.queryRowWithTimeout(ctx, query, userCode)
	err := row.Scan(&deviceCode.ID, &deviceCode.DeviceCode, &deviceCode.UserCode, 
		&deviceCode.VerificationURI, &deviceCode.VerificationURIComplete, &deviceCode.ClientID,
		&scopes, &deviceCode.ExpiresAt, &deviceCode.Interval, &userID, &deviceCode.Authorized,
		&accessTokenID, &deviceCode.CreatedAt)
	
	if err != nil {
		return nil, err
	}
	
	deviceCode.Scopes = []string(scopes)
	if userID.Valid {
		uid, err := uuid.Parse(userID.String)
		if err == nil {
			deviceCode.UserID = &uid
		}
	}
	if accessTokenID.Valid {
		atid, err := uuid.Parse(accessTokenID.String)
		if err == nil {
			deviceCode.AccessTokenID = &atid
		}
	}
	
	return deviceCode, nil
}

func (d *EnhancedDatabase) AuthorizeDeviceCode(ctx context.Context, userCode string, userID uuid.UUID) error {
	query := `UPDATE device_codes SET user_id = $1, authorized = true WHERE user_code = $2 AND expires_at > NOW()`
	
	result, err := d.execWithTimeout(ctx, query, userID, userCode)
	if err != nil {
		return err
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	
	return nil
}

// Cleanup operations for expired tokens and codes
func (d *EnhancedDatabase) CleanupExpiredTokens(ctx context.Context) error {
	queries := []string{
		`DELETE FROM refresh_tokens WHERE expires_at < NOW()`,
		`DELETE FROM access_tokens WHERE expires_at < NOW()`,
	}
	
	for _, query := range queries {
		_, err := d.execWithTimeout(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired tokens: %w", err)
		}
	}
	
	return nil
}

func (d *EnhancedDatabase) CleanupExpiredCodes(ctx context.Context) error {
	queries := []string{
		`DELETE FROM authorization_codes WHERE expires_at < NOW()`,
		`DELETE FROM device_codes WHERE expires_at < NOW()`,
	}
	
	for _, query := range queries {
		_, err := d.execWithTimeout(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired codes: %w", err)
		}
	}
	
	return nil
}