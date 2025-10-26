package tests

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"oauth-server/internal/admin"
	"oauth-server/internal/auth"
	"oauth-server/internal/config"
	"oauth-server/internal/db"
	"oauth-server/internal/dcr"
	"oauth-server/internal/handlers"
	"oauth-server/internal/oidc"
	"oauth-server/internal/scopes"
	"oauth-server/pkg/jwt"
)

// Mock database for testing
type MockDB struct {
	users         map[string]*db.User
	clients       map[string]*db.Client
	codes         map[string]*db.AuthorizationCode
	accessTokens  map[string]*db.AccessToken
	refreshTokens map[string]*db.RefreshToken
	deviceCodes   map[string]*db.DeviceCode
	clientSecrets map[uuid.UUID][]*db.ClientSecret // keyed by client UUID
}

func NewMockDatabase() *MockDB {
	return &MockDB{
		users:         make(map[string]*db.User),
		clients:       make(map[string]*db.Client),
		codes:         make(map[string]*db.AuthorizationCode),
		accessTokens:  make(map[string]*db.AccessToken),
		refreshTokens: make(map[string]*db.RefreshToken),
		deviceCodes:   make(map[string]*db.DeviceCode),
		clientSecrets: make(map[uuid.UUID][]*db.ClientSecret),
	}
}

func (m *MockDB) CreateUser(ctx context.Context, user *db.User) error {
	user.ID = uuid.New()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.Username] = user
	return nil
}

func (m *MockDB) GetUserByUsername(ctx context.Context, username string) (*db.User, error) {
	if user, exists := m.users[username]; exists {
		return user, nil
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) GetUserByID(ctx context.Context, id uuid.UUID) (*db.User, error) {
	for _, user := range m.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) CreateClient(ctx context.Context, client *db.Client) error {
	client.ID = uuid.New()
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()
	m.clients[client.ClientID] = client
	return nil
}

func (m *MockDB) GetClientByID(ctx context.Context, clientID string) (*db.Client, error) {
	if client, exists := m.clients[clientID]; exists {
		return client, nil
	}
	return nil, auth.ErrInvalidClient
}

func (m *MockDB) GetAllClients(ctx context.Context) ([]*db.Client, error) {
	clients := make([]*db.Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

func (m *MockDB) CreateAuthorizationCode(ctx context.Context, code *db.AuthorizationCode) error {
	code.ID = uuid.New()
	code.CreatedAt = time.Now()
	m.codes[code.Code] = code
	return nil
}

func (m *MockDB) GetAuthorizationCode(ctx context.Context, code string) (*db.AuthorizationCode, error) {
	if authCode, exists := m.codes[code]; exists && !authCode.Used && authCode.ExpiresAt.After(time.Now()) {
		return authCode, nil
	}
	return nil, auth.ErrExpiredCode
}

func (m *MockDB) MarkAuthorizationCodeUsed(ctx context.Context, code string) error {
	if authCode, exists := m.codes[code]; exists {
		authCode.Used = true
		return nil
	}
	return auth.ErrExpiredCode
}

func (m *MockDB) CreateAccessToken(ctx context.Context, token *db.AccessToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.accessTokens[token.Token] = token
	return nil
}

func (m *MockDB) CreateRefreshToken(ctx context.Context, token *db.RefreshToken) error {
	token.ID = uuid.New()
	token.CreatedAt = time.Now()
	m.refreshTokens[token.Token] = token
	return nil
}

func (m *MockDB) GetAccessToken(ctx context.Context, token string) (*db.AccessToken, error) {
	if accessToken, exists := m.accessTokens[token]; exists && !accessToken.Revoked && accessToken.ExpiresAt.After(time.Now()) {
		return accessToken, nil
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) GetRefreshToken(ctx context.Context, token string) (*db.RefreshToken, error) {
	if refreshToken, exists := m.refreshTokens[token]; exists && !refreshToken.Revoked && refreshToken.ExpiresAt.After(time.Now()) {
		return refreshToken, nil
	}
	return nil, auth.ErrInvalidCredentials
}

func (m *MockDB) RevokeAccessToken(ctx context.Context, tokenID uuid.UUID) error {
	for _, token := range m.accessTokens {
		if token.ID == tokenID {
			token.Revoked = true
			return nil
		}
	}
	return nil
}

func (m *MockDB) RevokeRefreshToken(ctx context.Context, token string) error {
	if refreshToken, exists := m.refreshTokens[token]; exists {
		refreshToken.Revoked = true
		return nil
	}
	return nil
}

func (m *MockDB) CreateDeviceCode(ctx context.Context, deviceCode *db.DeviceCode) error {
	deviceCode.ID = uuid.New()
	deviceCode.CreatedAt = time.Now()
	m.deviceCodes[deviceCode.DeviceCode] = deviceCode
	return nil
}

func (m *MockDB) GetDeviceCode(ctx context.Context, deviceCode string) (*db.DeviceCode, error) {
	if device, exists := m.deviceCodes[deviceCode]; exists && device.ExpiresAt.After(time.Now()) {
		return device, nil
	}
	return nil, auth.ErrExpiredToken
}

func (m *MockDB) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*db.DeviceCode, error) {
	for _, device := range m.deviceCodes {
		if device.UserCode == userCode && device.ExpiresAt.After(time.Now()) {
			return device, nil
		}
	}
	return nil, auth.ErrExpiredToken
}

func (m *MockDB) AuthorizeDeviceCode(ctx context.Context, userCode string, userID uuid.UUID) error {
	for _, device := range m.deviceCodes {
		if device.UserCode == userCode && device.ExpiresAt.After(time.Now()) {
			device.Authorized = true
			device.UserID = &userID
			return nil
		}
	}
	return auth.ErrExpiredToken
}

func (m *MockDB) Close() error {
	return nil
}

func (m *MockDB) CleanupExpiredTokens(ctx context.Context) error {
	return nil
}

func (m *MockDB) CleanupExpiredCodes(ctx context.Context) error {
	return nil
}

func (m *MockDB) GetDatabaseStats(ctx context.Context) (*db.DatabaseStats, error) {
	return &db.DatabaseStats{}, nil
}

func (m *MockDB) Ping(ctx context.Context) error {
	return nil
}

// Scope operations - basic implementations for testing
func (m *MockDB) CreateScope(ctx context.Context, scope *db.Scope) error {
	return nil
}

func (m *MockDB) GetScopeByName(ctx context.Context, name string) (*db.Scope, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *MockDB) GetAllScopes(ctx context.Context) ([]*db.Scope, error) {
	return nil, nil
}

func (m *MockDB) GetScopesByCategory(ctx context.Context, category string) ([]*db.Scope, error) {
	return nil, nil
}

func (m *MockDB) UpdateScope(ctx context.Context, scope *db.Scope) error {
	return nil
}

func (m *MockDB) DeleteScope(ctx context.Context, name string) error {
	return nil
}

func (m *MockDB) GetDefaultScopes(ctx context.Context) ([]*db.Scope, error) {
	return nil, nil
}

// Scope consent operations
func (m *MockDB) CreateScopeConsent(ctx context.Context, consent *db.ScopeConsent) error {
	return nil
}

func (m *MockDB) GetScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) (*db.ScopeConsent, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *MockDB) GetUserScopeConsents(ctx context.Context, userID uuid.UUID, clientID string) ([]*db.ScopeConsent, error) {
	return nil, nil
}

func (m *MockDB) UpdateScopeConsent(ctx context.Context, consent *db.ScopeConsent) error {
	return nil
}

func (m *MockDB) RevokeScopeConsent(ctx context.Context, userID uuid.UUID, clientID, scope string) error {
	return nil
}

func (m *MockDB) CleanupExpiredConsents(ctx context.Context) error {
	return nil
}

// Scope group operations
func (m *MockDB) CreateScopeGroup(ctx context.Context, group *db.ScopeGroup) error {
	return nil
}

func (m *MockDB) GetScopeGroup(ctx context.Context, id uuid.UUID) (*db.ScopeGroup, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *MockDB) GetAllScopeGroups(ctx context.Context) ([]*db.ScopeGroup, error) {
	return nil, nil
}

func (m *MockDB) UpdateScopeGroup(ctx context.Context, group *db.ScopeGroup) error {
	return nil
}

func (m *MockDB) DeleteScopeGroup(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *MockDB) AddScopeToGroup(ctx context.Context, scopeID, groupID uuid.UUID) error {
	return nil
}

func (m *MockDB) RemoveScopeFromGroup(ctx context.Context, scopeID, groupID uuid.UUID) error {
	return nil
}

func (m *MockDB) GetScopesByGroup(ctx context.Context, groupID uuid.UUID) ([]*db.Scope, error) {
	return nil, nil
}

// Dynamic Client Registration operations
func (m *MockDB) UpdateClient(ctx context.Context, client *db.Client) error {
	if existing, exists := m.clients[client.ClientID]; exists {
		*existing = *client
		return nil
	}
	return errors.New("client not found")
}

func (m *MockDB) DeleteClient(ctx context.Context, clientID string) error {
	delete(m.clients, clientID)
	return nil
}

func (m *MockDB) GetClientByRegistrationToken(ctx context.Context, token string) (*db.Client, error) {
	for _, client := range m.clients {
		if client.RegistrationAccessToken != nil && *client.RegistrationAccessToken == token {
			return client, nil
		}
	}
	return nil, errors.New("client not found")
}

// Client secret methods
func (m *MockDB) CreateClientSecret(ctx context.Context, secret *db.ClientSecret) error {
	secret.ID = uuid.New()
	secret.CreatedAt = time.Now()
	secret.UpdatedAt = time.Now()
	m.clientSecrets[secret.ClientID] = append(m.clientSecrets[secret.ClientID], secret)
	return nil
}

func (m *MockDB) GetActiveClientSecrets(ctx context.Context, clientID uuid.UUID) ([]*db.ClientSecret, error) {
	secrets := m.clientSecrets[clientID]
	active := []*db.ClientSecret{}
	now := time.Now()
	for _, secret := range secrets {
		if secret.RevokedAt == nil && (secret.ExpiresAt == nil || secret.ExpiresAt.After(now)) {
			active = append(active, secret)
		}
	}
	return active, nil
}

func (m *MockDB) GetClientSecretByID(ctx context.Context, secretID uuid.UUID) (*db.ClientSecret, error) {
	for _, secrets := range m.clientSecrets {
		for _, secret := range secrets {
			if secret.ID == secretID {
				return secret, nil
			}
		}
	}
	return nil, errors.New("secret not found")
}

func (m *MockDB) MarkSecretsNonPrimary(ctx context.Context, clientID uuid.UUID) error {
	secrets := m.clientSecrets[clientID]
	now := time.Now()
	for _, secret := range secrets {
		if secret.RevokedAt == nil {
			if secret.IsPrimary {
				secret.RotatedAt = &now
			}
			secret.IsPrimary = false
			secret.UpdatedAt = now
		}
	}
	return nil
}

func (m *MockDB) RevokeClientSecret(ctx context.Context, secretID uuid.UUID) error {
	for _, secrets := range m.clientSecrets {
		for _, secret := range secrets {
			if secret.ID == secretID && secret.RevokedAt == nil {
				now := time.Now()
				secret.RevokedAt = &now
				secret.UpdatedAt = now
				return nil
			}
		}
	}
	return errors.New("secret not found or already revoked")
}

func (m *MockDB) CleanupOldSecrets(ctx context.Context, clientID uuid.UUID, maxSecrets int) error {
	secrets := m.clientSecrets[clientID]
	if len(secrets) <= maxSecrets {
		return nil
	}

	// Sort by created_at desc and keep only the most recent maxSecrets
	// For simplicity in mock, we'll just truncate the slice
	// In production, this would be a proper SQL query
	m.clientSecrets[clientID] = secrets[:maxSecrets]
	return nil
}

func (m *MockDB) GetExpiringSecrets(ctx context.Context, withinDuration time.Duration) ([]*db.ClientSecret, error) {
	var expiring []*db.ClientSecret
	now := time.Now()
	threshold := now.Add(withinDuration)

	for _, secrets := range m.clientSecrets {
		for _, secret := range secrets {
			if secret.RevokedAt == nil && secret.ExpiresAt != nil {
				if secret.ExpiresAt.After(now) && secret.ExpiresAt.Before(threshold) {
					expiring = append(expiring, secret)
				}
			}
		}
	}
	return expiring, nil
}

func SetupTestAuth() (*auth.Service, *MockDB) {
	mockDatabase := NewMockDatabase()
	
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret",
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      7 * 24 * time.Hour,
			AuthorizationCodeTTL: 10 * time.Minute,
		},
		Security: config.SecurityConfig{
			MinPasswordLength: 8,
		},
		Server: config.ServerConfig{
			BaseURL: "http://localhost:8080",
		},
	}

	jwtManager := jwt.NewManager(cfg.Auth.JWTSecret)
	authService := auth.NewService(mockDatabase, jwtManager, cfg, nil)

	// Initialize default scopes for testing
	err := authService.InitializeDefaultScopes(context.Background())
	if err != nil {
		// For testing, we'll ignore scope initialization errors since MockDB doesn't fully implement scope operations
	}

	// Create test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	testUser := &db.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Scopes:   []string{"openid", "profile", "email", "read"},
	}
	mockDatabase.CreateUser(context.Background(), testUser)

	// Create test client
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	testClient := &db.Client{
		ClientID:     "test-client",
		ClientSecret: string(hashedSecret),
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:8080/callback"},
		Scopes:       []string{"openid", "profile", "email", "read", "write"},
		GrantTypes:   []string{"authorization_code", "refresh_token", "client_credentials", "password", "implicit", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:token-exchange"},
		IsPublic:     false,
	}
	mockDatabase.CreateClient(context.Background(), testClient)

	return authService, mockDatabase
}

func SetupTestHandler() (*handlers.Handler, *auth.Service, *MockDB) {
	authService, mockDB := SetupTestAuth()
	jwtManager := jwt.NewManager("test-secret")
	oidcService := oidc.NewService(jwtManager, "http://localhost:8080")
	
	// Setup DCR service
	scopeService := scopes.NewService(mockDB)
	dcrConfig := &dcr.Config{
		RegistrationEnabled:  true,
		DefaultScopes:        []string{"openid", "profile", "email"},
		DefaultGrantTypes:    []string{"authorization_code", "refresh_token"},
		DefaultResponseTypes: []string{"code"},
		BaseURL:             "http://localhost:8080",
	}
	dcrService := dcr.NewService(mockDB, scopeService, dcrConfig)
	
	// Setup Admin service
	adminConfig := &admin.Config{
		Version: "test-1.0.0",
	}
	adminService := admin.NewService(mockDB, authService, scopeService, adminConfig)
	
	handler := handlers.NewHandler(authService, mockDB, oidcService, dcrService, adminService)
	return handler, authService, mockDB
}